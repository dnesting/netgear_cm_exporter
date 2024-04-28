package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gocolly/colly"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "netgear_cm"

var (
	version   string
	revision  string
	branch    string
	buildUser string
	buildDate string
)

// Exporter represents an instance of the Netgear cable modem exporter.
type Exporter struct {
	baseUrl string
	// authHeaderValue string
	username, password string
	sessionId          string

	mu sync.Mutex

	// Exporter metrics.
	totalScrapes prometheus.Counter
	scrapeErrors prometheus.Counter

	// State metrics
	stateConnected      *prometheus.Desc
	stateBooted         *prometheus.Desc
	stateSecured        *prometheus.Desc
	stateIPProvisioning *prometheus.Desc

	uptime *prometheus.Desc

	// Downstream metrics.
	dsChannelSNR                    *prometheus.Desc
	dsChannelPower                  *prometheus.Desc
	dsChannelCodewordsNormal        *prometheus.Desc
	dsChannelCodewordsCorrectable   *prometheus.Desc
	dsChannelCodewordsUncorrectable *prometheus.Desc

	// Upstream metrics.
	usChannelPower      *prometheus.Desc
	usChannelSymbolRate *prometheus.Desc
}

// basicAuth returns the base64 encoding of the username and password
// separated by a colon. Borrowed the net/http package.
//func basicAuth(username, password string) string {
//	auth := fmt.Sprintf("%s:%s", username, password)
//	return base64.StdEncoding.EncodeToString([]byte(auth))
//}

// NewExporter returns an instance of Exporter configured with the modem's
// address, admin username and password.
func NewExporter(addr, username, password string) *Exporter {
	var (
		dsLabelNames = []string{"type", "channel", "lock_status", "modulation", "channel_id", "frequency"}
		usLabelNames = []string{"type", "channel", "lock_status", "channel_type", "channel_id", "frequency"}
	)

	return &Exporter{
		// Modem access details.
		baseUrl: "http://" + addr,
		//authHeaderValue: "Basic " + basicAuth(username, password),
		username: username,
		password: password,

		// Collection metrics.
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "status_scrapes_total",
			Help:      "Total number of scrapes of the modem status page.",
		}),
		scrapeErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "status_scrape_errors_total",
			Help:      "Total number of failed scrapes of the modem status page.",
		}),

		// State metrics
		stateConnected: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "state", "connected"),
			"The cable modem reports being connected",
			nil, nil,
		),
		stateBooted: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "state", "booted"),
			"The cable modem reports being booted",
			[]string{"file"}, nil,
		),
		stateSecured: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "state", "secured"),
			"The cable modem reports security is enabled",
			[]string{"mode"}, nil,
		),
		stateIPProvisioning: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "state", "ip_provisioning"),
			"The cable modem reports the IP provisioning mode",
			[]string{"mode"}, nil,
		),
		uptime: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "state", "uptime_secs"),
			"The cable modem reports the uptime in seconds",
			nil, nil,
		),

		// Downstream metrics.
		dsChannelSNR: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "downstream_channel", "snr_db"),
			"Downstream channel signal to noise ratio in dB.",
			dsLabelNames, nil,
		),
		dsChannelPower: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "downstream_channel", "power_dbmv"),
			"Downstream channel power in dBmV.",
			dsLabelNames, nil,
		),
		dsChannelCodewordsNormal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "downstream_channel", "codewords_normal_total"),
			"Downstream channel normal codewords.",
			dsLabelNames, nil,
		),
		dsChannelCodewordsCorrectable: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "downstream_channel", "codewords_correctable_total"),
			"Downstream channel correctable errors.",
			dsLabelNames, nil,
		),
		dsChannelCodewordsUncorrectable: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "downstream_channel", "codewords_uncorrectable_total"),
			"Downstream channel uncorrectable errors.",
			dsLabelNames, nil,
		),

		// Upstream metrics.
		usChannelPower: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "upstream_channel", "power_dbmv"),
			"Upstream channel power in dBmV.",
			usLabelNames, nil,
		),
		usChannelSymbolRate: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, "upstream_channel", "symbol_rate"),
			"Upstream channel symbol rate per second",
			usLabelNames, nil,
		),
	}
}

// Describe returns Prometheus metric descriptions for the exporter metrics.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// Exporter metrics.
	ch <- e.totalScrapes.Desc()
	ch <- e.scrapeErrors.Desc()
	// State metrics
	ch <- e.stateConnected
	ch <- e.stateBooted
	ch <- e.stateSecured
	ch <- e.stateIPProvisioning
	ch <- e.uptime
	// Downstream metrics.
	ch <- e.dsChannelSNR
	ch <- e.dsChannelPower
	ch <- e.dsChannelCodewordsNormal
	ch <- e.dsChannelCodewordsCorrectable
	ch <- e.dsChannelCodewordsUncorrectable
	// Upstream metrics.
	ch <- e.usChannelPower
	ch <- e.usChannelSymbolRate
}

/*
The CM interactions look like this:

GET /GenieLogin.asp
   This returns an HTML form that contains a hidden input field named "webToken" with a value that is used in the next step.

        <form id="target"  name="login" method="POST" action="/goform/GenieLogin">
            <input type="text" name="loginUsername" size="18" maxlength="32" value=""></td>
            <input type="password" name="loginPassword" size="18" maxlength="32" value=""></td>
            <button id="apply" value="1"  onClick="return checkData()" type="SUBMIT" name="login" class="button-apply">
            <input type="hidden" name="webToken" value=1714287085 />
        </form>

POST /goform/GenieLogin (application/x-www-form-urlencoded)
   This is the form submission from the previous step. If it succeeds, it returns a 302 to /GenieIndex.asp

GET /GenieIndex.asp
   This is the page we were redirected to, which sets a Cookie: SessionID=4339850

GET /DocsisStatus.asp
   This is the page that contains the data we want to scrape.  We need to send it the SessionID cookie we got from the /GenieIndex.asp page.
*/

// getLoginData retrieves /GenieLogin.asp, and returns the form data
// derived from the configured username, password, and the webToken value from the form.
func (e *Exporter) cmGetLoginForm() (postUrl string, loginData map[string]string, err error) {
	c := colly.NewCollector()

	loginData = make(map[string]string)
	c.OnHTML(`form[name="login"]`, func(elem *colly.HTMLElement) {
		elem.ForEach("input", func(_ int, el *colly.HTMLElement) {
			loginData[el.Attr("name")] = el.Attr("value")
		})

		loginData["loginUsername"] = e.username
		loginData["loginPassword"] = e.password

		postUrl = elem.Attr("action")
		if u, err2 := url.Parse(postUrl); err2 == nil {
			postUrl = elem.Request.URL.ResolveReference(u).String()
		}
	})

	c.OnError(func(r *colly.Response, err2 error) {
		err = err2
		log.Printf("failed to get login data: %d %s (err=%v)", r.StatusCode, http.StatusText(r.StatusCode), err)
	})

	c.Visit(e.baseUrl + "/GenieLogin.asp")
	return postUrl, loginData, err
}

func (e *Exporter) cmLogin(postUrl string, loginData map[string]string) (sessionId string, err error) {
	c := colly.NewCollector()

	c.OnError(func(r *colly.Response, err2 error) {
		err = err2
		log.Printf("failed to authenticate: %d %s (err=%v)", r.StatusCode, http.StatusText(r.StatusCode), err)
	})

	//c.OnRequest(func(r *colly.Request) {
	//	r.Headers.Set("Content-Type", "application/x-www-form-urlencoded")
	//})

	c.OnResponse(func(r *colly.Response) {
		sessionId = r.Headers.Get("Set-Cookie")

		// Extract the SessionID value from the cookie.
		if i := strings.Index(sessionId, "SessionID="); i != -1 {
			sessionId = sessionId[i+10:]
			if j := strings.Index(sessionId, ";"); j != -1 {
				sessionId = sessionId[:j]
			}
		}

		if sessionId == "" {
			err = fmt.Errorf("no SessionID cookie found")
		}
	})

	c.Post(postUrl, loginData)
	return sessionId, err
}

// logout visits /Logout.aspx with the session cookie and expects a 200
// func (e *Exporter) logout(sessionId string) (err error) {
// c := colly.NewCollector()
//
// c.OnError(func(r *colly.Response, err2 error) {
// err = err2
// log.Printf("failed to logout: %d %s (err=%v)", r.StatusCode, http.StatusText(r.StatusCode), err)
// })
//
// c.OnRequest(func(r *colly.Request) {
// r.Headers.Add("Cookie", "SessionID="+sessionId)
// })
//
// c.Visit(e.baseUrl + "/Logout.asp")
// return err
// }

func (e *Exporter) authenticate() (sessionId string, err error) {
	var postUrl string
	var loginData map[string]string
	log.Printf("auth: authenticating as %s...", e.username)

	postUrl, loginData, err = e.cmGetLoginForm()
	if err != nil {
		return "", err
	}
	loginKeys := make([]string, 0, len(loginData))
	for k := range loginData {
		loginKeys = append(loginKeys, k)
	}
	log.Printf("- using form fields: %s fields=%v", postUrl, loginKeys)
	sessionId, err = e.cmLogin(postUrl, loginData)
	if err != nil {
		log.Printf("auth: %v", err)
		return "", err
	}
	log.Printf("auth: success: %s", sessionId)
	return sessionId, nil
}

// Collect runs our scrape loop returning each Prometheus metric.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.totalScrapes.Inc()

	e.mu.Lock()
	defer e.mu.Unlock()

	var err error
	if e.sessionId != "" {
		log.Printf("auth: using existing session: %s", e.sessionId)
		err = e.collectDocsis(ch)
		if err != nil {
			log.Printf("collect: %v (will re-authenticate)", err)
			e.sessionId = ""
		}
	}
	if e.sessionId == "" {
		e.sessionId, err = e.authenticate()
		if err != nil {
			e.sessionId = ""
		} else {
			if err = e.collectDocsis(ch); err != nil {
				e.sessionId = ""
			}
		}
	}

	if e.sessionId == "" {
		log.Printf("unable to scrape")
		e.scrapeErrors.Inc()
	}

	e.totalScrapes.Collect(ch)
	e.scrapeErrors.Collect(ch)
}

func (e *Exporter) collectTableState(elem *colly.HTMLElement, ch chan<- prometheus.Metric) bool {
	// Rows have 3 columns: Procedure, Status, Comment
	// We will extract the the Status value for these Procedures:
	// - Connectivity State --> connected=1
	// - Boot State --> booted=1
	// - Configuration File --> configured{file=<status>}=1
	// - Security --> security.enabled=1
	// - IP Provisioning Mode --> ip_provisioning{mode=<status>}=1
	ok := false
	bootState := false
	elem.DOM.Find("tr").Each(func(i int, row *goquery.Selection) {
		if i == 0 {
			return // head
		}
		var (
			procedure string
			status    string
			note      string
		)
		row.Find("td").Each(func(j int, col *goquery.Selection) {
			text := strings.TrimSpace(col.Text())
			switch j {
			case 0:
				procedure = text
			case 1:
				status = text
			case 2:
				note = text
			}
		})
		switch procedure {
		case "Connectivity State":
			ok = true
			value := 0.0
			if status == "OK" {
				value = 1.0
			}
			ch <- prometheus.MustNewConstMetric(e.stateConnected, prometheus.GaugeValue, value)
		case "Boot State":
			if status == "OK" {
				bootState = true
			}
		case "Configuration File":
			value := 0.0
			if bootState {
				value = 1.0
			}
			ch <- prometheus.MustNewConstMetric(e.stateBooted, prometheus.GaugeValue, value, note)
		case "Security":
			value := 0.0
			if status == "Enable" {
				value = 1.0
			}
			ch <- prometheus.MustNewConstMetric(e.stateSecured, prometheus.GaugeValue, value, note)
		case "IP Provisioning Mode":
			ch <- prometheus.MustNewConstMetric(e.stateIPProvisioning, prometheus.GaugeValue, 1.0, status)
		}
	})
	return ok
}

func (e *Exporter) collectTableDownstream(kind string, elem *colly.HTMLElement, ch chan<- prometheus.Metric) bool {
	ok := false
	offset := 0
	if kind == "OFDM" {
		offset = 1
	}
	elem.DOM.Find("tr").Each(func(i int, row *goquery.Selection) {
		if i == 0 {
			return // head
		}
		var (
			channel       string
			lockStatus    string
			modulation    string
			channelID     string
			freqMHz       string
			power         float64
			snr           float64
			cwNormal      float64
			cwCorrected   float64
			cwUncorrected float64
		)
		ok = true
		row.Find("td").Each(func(j int, col *goquery.Selection) {
			text := strings.TrimSpace(col.Text())

			switch j {
			case 0:
				channel = text
			case 1:
				lockStatus = text
			case 2:
				modulation = text
			case 3:
				channelID = text
			case 4:
				{
					var freqHZ float64
					fmt.Sscanf(text, "%f Hz", &freqHZ)
					freqMHz = fmt.Sprintf("%0.2f MHz", freqHZ/1e6)
				}
			case 5:
				fmt.Sscanf(text, "%f dBmV", &power)
			case 6:
				fmt.Sscanf(text, "%f dB", &snr)
			case 7 + offset:
				fmt.Sscanf(text, "%f", &cwNormal)
			case 8 + offset:
				fmt.Sscanf(text, "%f", &cwCorrected)
			case 9 + offset:
				fmt.Sscanf(text, "%f", &cwUncorrected)
			}
		})
		labels := []string{kind, channel, lockStatus, modulation, channelID, freqMHz}

		ch <- prometheus.MustNewConstMetric(e.dsChannelSNR, prometheus.GaugeValue, snr, labels...)
		ch <- prometheus.MustNewConstMetric(e.dsChannelPower, prometheus.GaugeValue, power, labels...)
		ch <- prometheus.MustNewConstMetric(e.dsChannelCodewordsNormal, prometheus.CounterValue, cwNormal, labels...)
		ch <- prometheus.MustNewConstMetric(e.dsChannelCodewordsCorrectable, prometheus.CounterValue, cwCorrected, labels...)
		ch <- prometheus.MustNewConstMetric(e.dsChannelCodewordsUncorrectable, prometheus.CounterValue, cwUncorrected, labels...)
	})
	return ok
}

func (e *Exporter) collectTableUpstream(kind string, elem *colly.HTMLElement, ch chan<- prometheus.Metric) bool {
	ok := false
	elem.DOM.Find("tr").Each(func(i int, row *goquery.Selection) {
		if i == 0 {
			return // no rows were returned
		}
		var (
			channel    string
			lockStatus string
			modulation string
			channelID  string
			freqMHz    string
			power      float64
		)
		row.Find("td").Each(func(j int, col *goquery.Selection) {
			text := strings.TrimSpace(col.Text())
			ok = true
			switch j {
			case 0:
				channel = text
			case 1:
				lockStatus = text
			case 2:
				modulation = text
			case 3:
				channelID = text
			case 4:
				{
					var freqHZ float64
					fmt.Sscanf(text, "%f Hz", &freqHZ)
					freqMHz = fmt.Sprintf("%0.2f MHz", freqHZ/1e6)
				}
			case 5:
				fmt.Sscanf(text, "%f dBmV", &power)
			}
		})
		labels := []string{kind, channel, lockStatus, modulation, channelID, freqMHz}

		ch <- prometheus.MustNewConstMetric(e.usChannelPower, prometheus.GaugeValue, power, labels...)
	})
	return ok
}

func parseDuration(dur string) (time.Duration, error) {
	var h, m, s int
	dur = strings.TrimSpace(dur)
	n, err := fmt.Sscanf(dur, "%d:%d:%d", &h, &m, &s)
	if err != nil {
		return 0, err
	}
	if n != 3 {
		return 0, fmt.Errorf("expected 3 values, got %d", n)
	}
	return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second, nil
}

func (e *Exporter) collectDocsis(ch chan<- prometheus.Metric) (err error) {
	c := colly.NewCollector()

	// OnRequest callback adds basic auth header.
	c.OnRequest(func(r *colly.Request) {
		r.Headers.Add("Cookie", "SessionID="+e.sessionId)
		//r.Headers.Add("Authorization", e.authHeaderValue)
	})

	// OnError callback counts any errors that occur during scraping.
	c.OnError(func(r *colly.Response, err2 error) {
		err = err2
		log.Printf("scrape failed: %d %s (err=%v)", r.StatusCode, http.StatusText(r.StatusCode), err)
	})

	gotData := false
	c.OnHTML(`#startup_procedure_table tbody`, func(elem *colly.HTMLElement) {
		gotData = e.collectTableState(elem, ch)
		if !gotData {
			log.Println("no data found in startup_procedure_table")
		}
	})

	// Callback to parse the tbody block of table with id=dsTable, the downstream table info.
	c.OnHTML(`#dsTable tbody`, func(elem *colly.HTMLElement) {
		if e.collectTableDownstream("bonded", elem, ch) {
			gotData = true
		} else {
			log.Println("no data found in dsTable")
		}
	})
	c.OnHTML(`#d31dsTable tbody`, func(elem *colly.HTMLElement) {
		if e.collectTableDownstream("OFDM", elem, ch) {
			gotData = true
		} else {
			log.Println("no data found in d31dsTable")
		}
	})

	// Callback to parse the tbody block of table with id=usTable, the upstream channel info.
	c.OnHTML(`#usTable tbody`, func(elem *colly.HTMLElement) {
		if e.collectTableUpstream("bonded", elem, ch) {
			gotData = true
		} else {
			log.Println("no data found in usTable")
		}
	})

	c.OnHTML(`#d31usTable tbody`, func(elem *colly.HTMLElement) {
		if e.collectTableUpstream("OFDM", elem, ch) {
			gotData = true
		} else {
			log.Println("no data found in d31usTable")
		}
	})

	c.OnHTML(`#SystemUpTime`, func(elem *colly.HTMLElement) {
		// <b>System UpTime:&nbsp;</b> 0:30:59
		re := regexp.MustCompile(`\s*(\d+:\d+:\d+)$`)
		text := elem.Text
		matches := re.FindStringSubmatch(text)
		if len(matches) != 2 {
			log.Printf("failed to match uptime %v", text)
			return
		}
		d, err := parseDuration(matches[1])
		if err != nil {
			log.Printf("failed to parse uptime %v: %v", matches[1], err)
		} else {
			ch <- prometheus.MustNewConstMetric(e.uptime, prometheus.GaugeValue, d.Seconds())
		}
	})

	c.OnHTML(`html`, func(elem *colly.HTMLElement) {
		if !gotData {
			// print the entire HTML for debugging
			log.Printf("no data found: %s", elem.Text)
		}
	})

	u := e.baseUrl + "/DocsisStatus.asp"
	log.Printf("visiting %s", u)
	c.Visit(u)
	if err == nil && !gotData {
		err = fmt.Errorf("no data found")
	}
	return err
}

func main() {
	var (
		configFile  = flag.String("config.file", "netgear_cm_exporter.yml", "Path to configuration file.")
		showVersion = flag.Bool("version", false, "Print version information.")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("netgear_cm_exporter version=%s revision=%s branch=%s buildUser=%s buildDate=%s\n",
			version, revision, branch, buildUser, buildDate)
		os.Exit(0)
	}

	config, err := NewConfigFromFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	exporter := NewExporter(config.Modem.Address, config.Modem.Username, config.Modem.Password)

	prometheus.MustRegister(exporter)

	http.Handle(config.Telemetry.MetricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.Telemetry.MetricsPath, http.StatusMovedPermanently)
	})

	log.Printf("exporter listening on %s", config.Telemetry.ListenAddress)
	if err := http.ListenAndServe(config.Telemetry.ListenAddress, nil); err != nil {
		log.Fatalf("failed to start netgear exporter: %s", err)
	}
}
