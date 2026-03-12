package handlers

import (
	"expvar"
	"net/http"
)

func MetricsHandler() http.Handler {
	return expvar.Handler()
}
