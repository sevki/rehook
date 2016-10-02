package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/boltdb/bolt"
	"github.com/julienschmidt/httprouter"
)

const (
	// UserAgent header to use for outgoing HTTP requests
	UserAgent = "rehook/v0.1.1 (https://github.com/jstemmer/rehook)"
)

// flags
var (
	listenAddr = flag.String("http", ":9000", "Public HTTP listen address for incoming webhooks")
	adminAddr  = flag.String("admin", ":9001", "Private HTTP listen address for admin interface")
	database   = flag.String("db", "data.db", "Database file to use")
)

// Database constants
var (
	BucketHooks      = []byte("hooks")
	BucketComponents = []byte("components")
	BucketStats      = []byte("stats")

	start = time.Now()
)

func status(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	w.Write([]byte("OK\n"))
	w.Write([]byte(fmt.Sprintf("go:\t%s\n", runtime.Version())))
	w.Write([]byte(fmt.Sprintf("uptime:\t%s\n", time.Since(start).String())))

}

func main() {
	flag.Parse()

	// initialize database
	db, err := bolt.Open(*database, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Fatalf("Could not open database: %s", err)
	}
	defer db.Close()

	if err := db.Update(initBuckets); err != nil {
		log.Fatal(err)
	}

	hookStore := &HookStore{db}

	// webhooks
	hh := &HookHandler{hookStore, db}
	router := httprouter.New()
	router.GET("/_status", status)
	router.GET("/h/:id", hh.ReceiveHook)
	router.POST("/h/:id", hh.ReceiveHook)

	go func() {
		log.Printf("Listening on %s", *listenAddr)
		log.Print(http.ListenAndServe(*listenAddr, router))
	}()

	// admin interface
	ah := &AdminHandler{hookStore}
	arouter := httprouter.New()
	arouter.Handler("GET", "/public/*path", http.StripPrefix("/public", http.FileServer(http.Dir("public"))))
	arouter.GET("/", ah.Index)
	arouter.Handler("GET", "/hooks", http.RedirectHandler("/", http.StatusMovedPermanently))

	arouter.GET("/hooks/new", ah.NewHook)
	arouter.POST("/hooks", ah.CreateHook)
	arouter.GET("/hooks/edit/:id", ah.EditHook)
	arouter.POST("/hooks/edit/:id", ah.UpdateHook)

	arouter.GET("/hooks/edit/:id/add", ah.AddComponent)
	arouter.POST("/hooks/edit/:id/create", ah.CreateComponent)
	arouter.GET("/hooks/edit/:id/edit/:c", ah.EditComponent)
	arouter.POST("/hooks/edit/:id/update/:c", ah.UpdateComponent)

	log.Printf("Admin interface on %s", *adminAddr)
	log.Print(http.ListenAndServe(*adminAddr, arouter))
}

func initBuckets(t *bolt.Tx) error {
	for _, name := range [][]byte{BucketHooks, BucketStats, BucketComponents} {
		if _, err := t.CreateBucketIfNotExists(name); err != nil {
			return err
		}
	}
	return nil
}
