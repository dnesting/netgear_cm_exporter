all: secret

secret: cm-secret.secret.yaml

kubeseal: cm-secret.kubeseal.yaml

cm-secret.secret.yaml: ../netgear_cm_exporter.yml cm-secret.tmpl.yaml
	base64 <../netgear_cm_exporter.yml | sed 's/^/    /' | cat cm-secret.tmpl.yaml - > $@

cm-secret.kubeseal.yaml: cm-secret.secret.yaml
	kubeseal --format yaml  < $< > $@
