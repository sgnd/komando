package cli

import (
	"encoding/json"
	"testing"
)

func obj(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPodTrouble(t *testing.T) {
	for js, want := range map[string]string{
		`{"phase":"Running","containerStatuses":[{"name":"api","ready":false,"state":{"waiting":{"reason":"CrashLoopBackOff"}}}]}`: "api: CrashLoopBackOff",
		`{"phase":"Pending","containerStatuses":[{"name":"api","state":{"waiting":{"reason":"ImagePullBackOff"}}}]}`:               "api: ImagePullBackOff",
		`{"phase":"Pending","containerStatuses":[{"name":"api","state":{"waiting":{"reason":"ContainerCreating"}}}]}`:              "",
		`{"phase":"Running","containerStatuses":[{"name":"api","ready":true,"state":{"running":{}}}]}`:                             "",
		`{"phase":"Running","containerStatuses":[{"name":"w","ready":false,"state":{"terminated":{"reason":"OOMKilled"}}}]}`:       "w: OOMKilled",
	} {
		if got := podTrouble(obj(t, js)); got != want {
			t.Errorf("%s: %q, want %q", js, got, want)
		}
	}
}

func TestSummarizeMoreKinds(t *testing.T) {
	job := summarize("Job", obj(t, `{"metadata":{"name":"m"},"spec":{"completions":2},"status":{"succeeded":2,"conditions":[{"type":"Complete","status":"True"}]}}`))
	if job["completions"] != "2/2" || job["status"] != "complete" {
		t.Errorf("job: %v", job)
	}
	ing := summarize("Ingress", obj(t, `{"metadata":{"name":"w"},"spec":{"rules":[{"host":"a.example"},{"host":"b.example"}]},"status":{"loadBalancer":{"ingress":[{"ip":"10.0.0.9"}]}}}`))
	if ing["hosts"] != "a.example,b.example" || ing["address"] != "10.0.0.9" {
		t.Errorf("ingress: %v", ing)
	}
	ev := summarize("Event", obj(t, `{"metadata":{"name":"e"},"type":"Warning","reason":"BackOff","message":"restarting","count":3,"involvedObject":{"kind":"Pod","name":"api-1"},"lastTimestamp":"2026-01-01T00:00:00Z"}`))
	if ev["object"] != "pod/api-1" || ev["reason"] != "BackOff" || ev["count"] != 3 {
		t.Errorf("event: %v", ev)
	}
}

func TestMatchLabels(t *testing.T) {
	d := obj(t, `{"kind":"Deployment","spec":{"selector":{"matchLabels":{"tier":"web","app":"api"}}}}`)
	if got := matchLabels(d); got != "app=api,tier=web" {
		t.Errorf("deployment selector %q", got)
	}
	s := obj(t, `{"kind":"Service","spec":{"selector":{"app":"api"}}}`)
	if got := matchLabels(s); got != "app=api" {
		t.Errorf("service selector %q", got)
	}
}

func TestRolloutState(t *testing.T) {
	for js, want := range map[string]bool{
		`{"metadata":{"generation":2},"spec":{"replicas":2},"status":{"observedGeneration":2,"replicas":2,"updatedReplicas":2,"availableReplicas":2}}`: true,
		`{"metadata":{"generation":3},"spec":{"replicas":2},"status":{"observedGeneration":2,"replicas":2,"updatedReplicas":2,"availableReplicas":2}}`: false,
		`{"metadata":{"generation":2},"spec":{"replicas":2},"status":{"observedGeneration":2,"replicas":3,"updatedReplicas":2,"availableReplicas":2}}`: false,
		`{"metadata":{"generation":2},"spec":{"replicas":2},"status":{"observedGeneration":2,"replicas":2,"updatedReplicas":2,"availableReplicas":1}}`: false,
	} {
		if done, _, _ := rolloutState("Deployment", obj(t, js)); done != want {
			t.Errorf("%s: done=%v, want %v", js, done, want)
		}
	}
	stuck := obj(t, `{"metadata":{"generation":1},"status":{"observedGeneration":1,"conditions":[{"type":"Progressing","status":"False","reason":"ProgressDeadlineExceeded","message":"took too long"}]}}`)
	if _, msg, failed := rolloutState("Deployment", stuck); !failed || msg != "took too long" {
		t.Errorf("ProgressDeadlineExceeded must fail the rollout: %v %q", failed, msg)
	}
}

func TestPickContainer(t *testing.T) {
	one := obj(t, `{"spec":{"template":{"spec":{"containers":[{"name":"api","image":"a:1"}]}}}}`)
	if n, img, err := pickContainer(one, ""); err != nil || n != "api" || img != "a:1" {
		t.Errorf("single container: %v %v %v", n, img, err)
	}
	two := obj(t, `{"spec":{"template":{"spec":{"containers":[{"name":"api","image":"a:1"},{"name":"proxy","image":"p:1"}]}}}}`)
	if _, _, err := pickContainer(two, ""); err == nil {
		t.Error("two containers need --container")
	}
	if n, _, err := pickContainer(two, "proxy"); err != nil || n != "proxy" {
		t.Errorf("named container: %v %v", n, err)
	}
	if _, _, err := pickContainer(two, "nope"); err == nil || toErr(err).Code != "CONTAINER_NOT_FOUND" {
		t.Errorf("unknown container: %v", err)
	}
}
