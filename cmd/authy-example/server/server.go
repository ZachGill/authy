package main

import (
	"context"
	"log"
	"net/http"
	"sync"

	middleware "github.com/ZachGill/authy/cmd/authy"
	"github.com/gorilla/mux"
)

// Server starts the applications HTTP Server
type Server struct {
	ServerMutex *sync.Mutex
	WaitGroup   *sync.WaitGroup

	HTTPListenAddr string
	HTTPLogger     *log.Logger

	// The healthcheck should return a 200 response if the service is up and the
	// request sent is authenticated.
	Healthcheck http.Handler
	// Map of API keys (public to private)
	KeyMap map[string]string

	httpServer *http.Server
}

// Start starts the http.Server
func (server *Server) Start() {

	router := server.Router()

	server.ServerMutex.Lock()
	server.httpServer = &http.Server{
		Addr:     server.HTTPListenAddr,
		Handler:  router,
		ErrorLog: server.HTTPLogger,
	}
	server.ServerMutex.Unlock()

	log.Println("I'm starting the server")
	if err := server.httpServer.ListenAndServe(); err != nil {
		server.HTTPLogger.Println("Unable to listen and serve", err.Error())
	}
}

// Stop tells the httpServer to shutdown
func (server *Server) Stop(ctx context.Context) {
	server.ServerMutex.Lock()
	defer server.ServerMutex.Unlock()

	err := server.httpServer.Shutdown(ctx)

	if err != nil {
		server.HTTPLogger.Print("unable to shutdown. error:", err.Error())
	}
	log.Println("I'm stopping the server")
	server.WaitGroup.Done()
}

// Router parses the request URI and supplies the needed handler
func (server *Server) Router() *mux.Router {
	r := mux.NewRouter()

	r.Handle("/", middleware.NewHandler(server.Healthcheck, server.KeyMap)).Methods("GET")

	return r
}
