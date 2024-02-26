ip netns $1
ip netns exec $1 ip link set dev lo up
ip netns exec $1 <command>
