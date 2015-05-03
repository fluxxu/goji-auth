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
		auth := r.Header.Get("Authorization")
		methodLen := len("Session ")
		if len(auth) > methodLen {
			sid := auth[methodLen:]
			if sid != "" {
				sess, err = sessionStore.Load(sid)
				if err != nil {
					util.Response(w).Error("load session error: " + err.Error())
					return
				}
				if sess != nil {
					c.Env["session"] = sess
				}
			}
		}
		h.ServeHTTP(w, r)
		if sess != nil {
			sessionStore.Save(sess)
		}
		//fmt.Println("session out")
	}
	return http.HandlerFunc(fn)
}

var skipAuthPath = make(map[string][]string)

func Skip(path string, args ...string) {
	skipAuthPath[path] = args
}

func authMiddleware(c *web.C, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// allow POST /token
		if r.Method == "POST" && r.URL.Path == muxBase+"/token" {
			h.ServeHTTP(w, r)
			return
		}

		// skip
		if methods, ok := skipAuthPath[r.URL.Path]; ok {
			if len(methods) == 0 {
				h.ServeHTTP(w, r)
				return
			} else {
				if util.IndexOfString(methods, r.Method) != -1 {
					h.ServeHTTP(w, r)
					return
				}
			}
		}

		// allow login user only
		if _, ok := c.Env["session"]; !ok {
			util.Response(w).Error("Unauthorized", 401)
			return
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}
