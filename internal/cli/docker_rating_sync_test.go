package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/policy"
)

// The exec rules for docker text stop on the same condition as the docker
// area's own rating, until that area is removed. Exec is left out on
// purpose: through exec, the command it runs in the container is checked.
func TestDockerRatingMatchesDockerArea(t *testing.T) {
	for _, c := range []string{
		"rm web", "rm -f web api", "rmi nginx", "container rm web", "image rm x", "volume rm d", "network rm n",
		"service rm a", "stack rm s", "node rm n", "secret rm s", "config rm c", "plugin rm p", "start rm",
		"system prune -f", "image prune", "container prune", "volume prune", "network prune", "builder prune", "prune",
		"kill web", "container kill web", "swarm leave --force", "swarm init", "node demote n2",
		"node update --availability drain n2", "node update --label-add a=b n2", "service scale api=0", "service scale api=2",
		"service update --replicas 0 api", "service update --replicas=3 api", "stack deploy --prune -c s.yml p", "stack deploy -c s.yml p",
		"cp web:/x /tmp/x", "container cp web:/x /tmp/x",
		"run --privileged img", "run -v /:/host img", "run -itv/:/h img", "run -v /etc/localtime:/etc/localtime:ro img",
		"run -v /etc/nginx:/etc/nginx img", "run -v /root/.ssh:/k:ro img", "run -v /srv/data:/data img", "run --pid=host img",
		"run --network host img", "run --mount type=bind,source=/etc,target=/x img", "run --mount type=bind,source=/etc,target=/x,readonly img",
		"run --mount type=bind,source=/var/run/docker.sock,target=/s img", "create --cap-add SYS_ADMIN img",
		"service create --privileged img", "service update --mount-add type=bind,src=/,dst=/h a",
		"plugin install vieux/sshfs", "plugin enable p", "volume create -o device=/etc --opt o=bind v", "volume create v",
		"ps -a", "logs web", "images", "inspect web", "volume ls", "restart web", "start web", "stop web", "pull nginx", "run -d img",
		"-H ssh://x rm web", "--context prod system prune", "-l debug ps",
		"compose rm -f", "compose down", "compose down -v", "compose -f p.yml down --rmi all", "compose kill", "compose cp app:/x /y",
		"compose up -d", "compose ps", "compose run app sh", "compose run --privileged app sh", "compose -p p logs",
	} {
		args := strings.Fields(c)
		area := classifyDocker(args) == driver.RiskDestructive
		rated := policy.DockerRating(args) != ""
		if area != rated {
			t.Errorf("docker %s: docker area destructive=%v, exec rule %q", c, area, policy.DockerRating(args))
		}
	}
}
