package agent

type PromptEvent struct {
	FilePath      string
	Category      string
	MatchedKind   string
	PID           int
	Exe           string
	HumanIdentity string
	IdentityKey   string
	ExeOnlyKey    string
}

type PromptBus struct {
	c chan PromptEvent
}

func NewPromptBus(buf int) *PromptBus { return &PromptBus{c: make(chan PromptEvent, buf)} }

func (b *PromptBus) C() <-chan PromptEvent { return b.c }

// Publish drops the event if the bus is full (engine never blocks on prompt UX).
func (b *PromptBus) Publish(e PromptEvent) {
	select {
	case b.c <- e:
	default:
	}
}
