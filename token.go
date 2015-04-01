package auth

type Token struct {
	Id   string      `json:"id"`
	User interface{} `json:"user"`
}
