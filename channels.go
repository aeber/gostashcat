package gostashcat

import (
	"fmt"
	"net/url"
	"strconv"
)

type MembershipInfo struct {
	IsMember     bool   `json:"is_member"`
	Joined       string `json:"joined"`
	Confirmation string `json:"confirmation"`
	MayManage    bool   `json:"may_manage"`
	Write        bool   `json:"write"`
	// Muted
}

type ChannelInfoIDString struct {
	ID int `json:"id,string"`
	ChannelInfoRadikal
}

type ChannelInfoIDInt struct {
	ID int `json:"id"`
	ChannelInfoRadikal
}

type ChannelInfo struct {
	ID int
	ChannelInfoRadikal
}

type ChannelInfoRadikal struct {
	Name string `json:"name"`
	// Image
	Description string `json:"description"`
	// GroupID
	// LDAPName
	CompanyID string `json:"company"`
	Type      string `json:"type"`
	Visible   bool   `json:"visible"`
	// Password
	Encrypted                bool           `json:"encrypted"`
	LastAction               string         `json:"last_action"`
	LastActivity             FlexInt        `json:"last_activity"`
	Writable                 string         `json:"writable"`
	Inviteable               string         `json:"inviteable"`
	CanLeave                 bool           `json:"can_leave"`
	ShowMembershipActivities bool           `json:"show_membership_activities"`
	UserCount                int            `json:"user_count"`
	PendingCount             int            `json:"pending_count"`
	NumMembersWithoutKeys    int            `json:"num_members_without_keys"`
	Membership               MembershipInfo `json:"membership"`
	Key                      string         `json:"key"`
	// KeyRequested
	Unread int `json:"unread"`
	// MembersWithoutKeys
}

type ChannelInfoResponsePayload struct {
	Channel ChannelInfoIDInt `json:"channels"`
}

type ChannelInfoResponse struct {
	Status    Status                     `json:"status"`
	Payload   ChannelInfoResponsePayload `json:"payload"`
	Signature string                     `json:"signature"`
}

type SubscribedChannelsResponsePayload struct {
	Channels []ChannelInfoIDString `json:"channels"`
}

type SubscribedChannelsResponse struct {
	Status    Status                            `json:"status"`
	Payload   SubscribedChannelsResponsePayload `json:"payload"`
	Signature string                            `json:"signature"`
}

func (api *Client) GetChannelInfo(channelID int) (ChannelInfo, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("channel_id", fmt.Sprintf("%d", channelID))
	v.Set("without_members", strconv.FormatBool(true))

	response := ChannelInfoResponse{}

	err := api.postMethod("channels/info", v, &response)
	if err != nil {
		return ChannelInfo{}, err
	}

	return ChannelInfo(response.Payload.Channel), nil
}

func (api *Client) GetSubscribedChannels() ([]ChannelInfo, error) {
	v := url.Values{}
	v.Set("client_key", api.clientKey)
	v.Set("device_id", api.deviceID)
	v.Set("company", api.UserInfo.Roles[0].CompanyId)

	response := SubscribedChannelsResponse{}

	err := api.postMethod("channels/subscripted", v, &response)
	if err != nil {
		return []ChannelInfo{}, err
	}

	var retChannels []ChannelInfo
	for _, c := range response.Payload.Channels {
		retChannels = append(retChannels, ChannelInfo(c))
	}

	return retChannels, nil
}
