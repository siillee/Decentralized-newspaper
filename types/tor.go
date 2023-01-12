package types

// -----------------------------------------------------------------------------
// KeyExchangeRequestMessage

// NewEmpty implements types.Message.
func (k KeyExchangeRequestMessage) NewEmpty() Message {
	return &KeyExchangeRequestMessage{}
}

// Name implements types.Message.
func (k KeyExchangeRequestMessage) Name() string {
	return "keyexchangerequest"
}

// String implements types.Message.
func (k KeyExchangeRequestMessage) String() string {
	return k.Name()
}

// HTML implements types.Message.
func (k KeyExchangeRequestMessage) HTML() string {
	return k.String()
}

// -----------------------------------------------------------------------------
// KeyExchangeReplyMessage

// NewEmpty implements types.Message.
func (k KeyExchangeReplyMessage) NewEmpty() Message {
	return &KeyExchangeReplyMessage{}
}

// Name implements types.Message.
func (k KeyExchangeReplyMessage) Name() string {
	return "keyexchangereply"
}

// String implements types.Message.
func (k KeyExchangeReplyMessage) String() string {
	return k.Name()
}

// HTML implements types.Message.
func (k KeyExchangeReplyMessage) HTML() string {
	return k.String()
}

// -----------------------------------------------------------------------------
// OnionMessage

// NewEmpty implements types.Message.
func (o OnionMessage) NewEmpty() Message {
	return &OnionMessage{}
}

// Name implements types.Message.
func (o OnionMessage) Name() string {
	return "onion"
}

// String implements types.Message.
func (o OnionMessage) String() string {
	return o.Name()
}

// HTML implements types.Message.
func (o OnionMessage) HTML() string {
	return o.String()
}

// -----------------------------------------------------------------------------
// AnonymousArticleSummaryMessage

// NewEmpty implements types.Message.
func (a AnonymousArticleSummaryMessage) NewEmpty() Message {
	return &AnonymousArticleSummaryMessage{}
}

// Name implements types.Message.
func (a AnonymousArticleSummaryMessage) Name() string {
	return "anonymousarticlesummarymessage"
}

// String implements types.Message.
func (a AnonymousArticleSummaryMessage) String() string {
	return a.Name()
}

// HTML implements types.Message.
func (a AnonymousArticleSummaryMessage) HTML() string {
	return a.String()
}

// -----------------------------------------------------------------------------
// AnonymousDownloadRequestMessage

// NewEmpty implements types.Message.
func (a AnonymousDownloadRequestMessage) NewEmpty() Message {
	return &AnonymousDownloadRequestMessage{}
}

// Name implements types.Message.
func (a AnonymousDownloadRequestMessage) Name() string {
	return "anonymousdownloadrequestmessage"
}

// String implements types.Message.
func (a AnonymousDownloadRequestMessage) String() string {
	return a.Name()
}

// HTML implements types.Message.
func (a AnonymousDownloadRequestMessage) HTML() string {
	return a.String()
}

// -----------------------------------------------------------------------------
// AnonymousDownloadReplyMessage

// NewEmpty implements types.Message.
func (a AnonymousDownloadReplyMessage) NewEmpty() Message {
	return &AnonymousDownloadReplyMessage{}
}

// Name implements types.Message.
func (a AnonymousDownloadReplyMessage) Name() string {
	return "anonymousdownloadreplymessage"
}

// String implements types.Message.
func (a AnonymousDownloadReplyMessage) String() string {
	return a.Name()
}

// HTML implements types.Message.
func (a AnonymousDownloadReplyMessage) HTML() string {
	return a.String()
}
