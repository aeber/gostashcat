package gostashcat

type Role struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Global    string `json:"global"`
	CompanyId string `json:"company_id"`
	Time      string `json:"time"`
}
