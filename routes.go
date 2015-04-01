package auth

import (
	"github.com/fluxxu/session"
	"github.com/fluxxu/util"
	"github.com/nu7hatch/gouuid"
	"github.com/zenazn/goji/web"
	"net/http"
)

func RouteGetUser(c web.C, w http.ResponseWriter, r *http.Request) {
	sess := c.Env["session"].(*session.Session)
	token := &Token{Id: sess.Id(), User: sess.Get("user"), ExpiresAt: sess.ExpiresAt()}
	util.Response(w).Send(200, token)
}

func RouteLogin(c web.C, w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var body req
	if err := util.Request(r).DecodeBody(&body); err != nil {
		util.Response(w).Error("can not parse body: "+err.Error(), 400)
		return
	}

	user, err := opts.UserFinder.FindUserByEmailAndPassword(body.Email, body.Password)
	if err != nil {
		if err == ErrUserNotFound {
			util.Response(w).Error("login failed", 401)
			return
		}
		util.Response(w).Error("find user error: " + err.Error())
		return
	}

	// create session
	sid, err := uuid.NewV4()
	if err != nil {
		util.Response(w).Error("gen session id: " + err.Error())
		return
	}

	sess := session.NewSession(sid.String())
	sess.Set("user", user)

	if err = sessionStore.Save(sess); err != nil {
		util.Response(w).Error("create session: " + err.Error())
		return
	}

	token := &Token{Id: sess.Id(), User: user, ExpiresAt: sess.ExpiresAt()}

	util.Response(w).Send(200, token)
}

func RouteLogout(c web.C, w http.ResponseWriter, r *http.Request) {
	sess := c.Env["session"].(*session.Session)
	sessionStore.Revoke(sess.Id())
	w.WriteHeader(200)
}
