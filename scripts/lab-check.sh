#!/usr/bin/env bash
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
require_root

fail=0
pingq() { ip netns exec "$1" ping -c1 -W1 -q "${@:2}" >/dev/null 2>&1; }

echo "== Underlay (vh1 to each host)"
for plane in a b; do
  for j in "${HOSTS[@]}"; do
    if [[ $plane == a ]]; then ip=$(a_ip "$j"); else ip=$(b_ip "$j"); fi
    if pingq vh1 "$ip"; then s=ok; else s=FAIL; fail=1; fi
    printf '  plane %s -> vh%s (%s): %s\n' "$plane" "$j" "$ip" "$s"
  done
done

echo "== Overlay ping matrix (rows = source, '.' ok, 'X' fail)"
names=()
for i in "${HOSTS[@]}"; do for j in "${CONTAINERS[@]}"; do names+=("$(cont_name "$i" "$j")"); done; done
printf '      '; for d in "${names[@]}"; do printf '%-4s' "$d"; done; echo
for si in "${HOSTS[@]}"; do
  for sj in "${CONTAINERS[@]}"; do
    src=$(cont_name "$si" "$sj")
    printf '%-6s' "$src"
    for di in "${HOSTS[@]}"; do
      for dj in "${CONTAINERS[@]}"; do
        dst=$(cont_name "$di" "$dj")
        if [[ $src == "$dst" ]]; then printf '%-4s' '-'
        elif pingq "$src" "$(cont_ip "$di" "$dj")"; then printf '%-4s' '.'
        else printf '%-4s' 'X'; fail=1; fi
      done
    done
    echo
  done
done

echo "== MTU boundary (c11 -> c43, DF set, overlay MTU $OVERLAY_MTU)"
big=$(( OVERLAY_MTU - 28 ))
if pingq c11 -M do -s "$big" "$(cont_ip 4 3)"; then
  echo "  payload $big passes: ok"
else
  echo "  payload $big FAILED"; fail=1
fi
if pingq c11 -M do -s $(( big + 1 )) "$(cont_ip 4 3)"; then
  echo "  payload $((big+1)) passed but should not"; fail=1
else
  echo "  payload $((big+1)) rejected: ok"
fi

echo "== vxlan100 MTU on vh1: $(ip -n vh1 -o link show vxlan100 | sed -n 's/.*mtu \([0-9]*\).*/\1/p')"

if (( fail )); then echo "RESULT: FAIL"; exit 1; fi
echo "RESULT: PASS"
