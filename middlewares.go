package auth

import (
	"github.com/fluxxu/session"
	"github.com/fluxxu/util"
	"github.com/zenazn/goji/web"
	"net/http"
)

func sessionMiddleware(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		//fmt.Println("session in")
		var sess *session.Session = nil
		var err error
		sid := r.Header.Get("X-TOKEN")
		if sid != "" {
			sess, err = sessionStore.Load(sid)
			if err != nil {
				util.Response(w).Error("load session error: " + err.Error())
				return
			}
			c.Env["session"] = sess
		}
		h.ServeHTTP(w, r)
		if sess != nil {
			sessionStore.Save(sess)
		}
		//fmt.Println("session out")
	}
	return http.HandlerFunc(fn)
}

var skipAuthPath = make(map[string]bool)

func Skip(path string) {
	skipAuthPath[path] = true
}

func authMiddleware(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// allow POST /api/token
		if r.Method == "POST" && r.URL.Path == "/api/token" {
			h.ServeHTTP(w, r)
			return
		}

		// skip
		if _, ok := skipAuthPath[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}

		// allow login user only
		if c.Env["session"] == nil {
			util.Response(w).Error("Unauthorized", 401)
			return
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
