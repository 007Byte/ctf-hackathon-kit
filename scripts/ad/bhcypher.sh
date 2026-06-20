#!/usr/bin/env bash
#
# bhcypher.sh - BloodHound CE quick-win Cypher runner
# -----------------------------------------------------------------------------
# Runs high-value attack-path Cypher queries directly against the BloodHound CE
# Neo4j database (the one deployed in /opt/tools/c2/bloodhound). No GUI clicking:
# get the juicy targets in your terminal right after uploading collection data.
#
# Queries it can run (by name, or 'all'):
#   das            - Domain Admins (members)
#   kerberoastable - users with SPNs (Kerberoast targets)
#   asrep          - users not requiring Kerberos preauth (AS-REP roast)
#   unconstrained  - computers/users with unconstrained delegation
#   constrained    - principals with constrained delegation
#   dcsync         - principals with DCSync (GetChanges/GetChangesAll)
#   path-to-da     - shortest paths from OWNED nodes to Domain Admins
#   owned-adminto  - what your OWNED principals are local admin on
#   highvalue      - shortest paths from owned -> any High Value target
#   sessions       - where high-value users have sessions
#
# Mark nodes as Owned in the BloodHound GUI first to make the 'owned-*' and
# 'path-to-da' queries meaningful.
# -----------------------------------------------------------------------------
# AUTHORIZED USE ONLY: analysis of data you collected from an in-scope domain.
# -----------------------------------------------------------------------------
#
# USAGE:
#   ./bhcypher.sh <query_name | all>
#
# ENV (override if your deploy differs):
#   BHCE_CONTAINER  (default: auto-detected graph-db container)
#   BHCE_USER       (default: neo4j)
#   BHCE_PASS       (default: bloodhoundcommunityedition)
#
# DEPENDENCIES: docker (BloodHound CE running). Uses cypher-shell inside the
#               Neo4j container, so nothing extra to install on the host.
# -----------------------------------------------------------------------------

set -euo pipefail

c_info(){ printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
c_ok(){   printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
c_err(){  printf '\033[1;31m[-]\033[0m %s\n' "$*" >&2; }
c_step(){ printf '\n\033[1;36m===== %s =====\033[0m\n' "$*"; }

WHICH="${1:-}"; [ -z "$WHICH" ] && { sed -n '2,42p' "$0"; exit 1; }
DOCKER="docker"; docker ps >/dev/null 2>&1 || DOCKER="sudo docker"
BHCE_CONTAINER="${BHCE_CONTAINER:-$($DOCKER ps --format '{{.Names}}' | grep -iE 'graph-db|neo4j' | head -1)}"
BHCE_USER="${BHCE_USER:-neo4j}"
BHCE_PASS="${BHCE_PASS:-bloodhoundcommunityedition}"
[ -z "$BHCE_CONTAINER" ] && { c_err "No BloodHound Neo4j container running (start BloodHound CE first)."; exit 1; }

run(){ # $1 title  $2 cypher
  c_step "$1"
  printf '%s\n' "$2" | $DOCKER exec -i "$BHCE_CONTAINER" cypher-shell -u "$BHCE_USER" -p "$BHCE_PASS" --format plain 2>&1 \
    || c_err "query failed (check BHCE_PASS / container name)"
}

declare -A Q=(
[das]='MATCH (g:Group) WHERE g.name STARTS WITH "DOMAIN ADMINS@" MATCH (n)-[:MemberOf*1..]->(g) RETURN n.name AS member ORDER BY member;'
[kerberoastable]='MATCH (u:User) WHERE u.hasspn=true AND u.enabled=true RETURN u.name AS user, u.serviceprincipalnames AS spns ORDER BY user;'
[asrep]='MATCH (u:User) WHERE u.dontreqpreauth=true AND u.enabled=true RETURN u.name AS user;'
[unconstrained]='MATCH (n) WHERE n.unconstraineddelegation=true RETURN labels(n)[0] AS type, n.name AS name;'
[constrained]='MATCH (n) WHERE n.allowedtodelegate IS NOT NULL RETURN n.name AS name, n.allowedtodelegate AS to;'
[dcsync]='MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll*1..]->(d:Domain) RETURN DISTINCT n.name AS principal ORDER BY principal;'
[path-to-da]='MATCH (o {owned:true}) MATCH (g:Group) WHERE g.name STARTS WITH "DOMAIN ADMINS@" MATCH p=shortestPath((o)-[*1..]->(g)) RETURN o.name AS from, length(p) AS hops ORDER BY hops LIMIT 25;'
[owned-adminto]='MATCH (o {owned:true})-[:AdminTo|MemberOf*1..]->(c:Computer) RETURN DISTINCT o.name AS owned, c.name AS admin_on ORDER BY owned;'
[highvalue]='MATCH (o {owned:true}) MATCH (h {highvalue:true}) MATCH p=shortestPath((o)-[*1..]->(h)) RETURN o.name AS from, h.name AS target, length(p) AS hops ORDER BY hops LIMIT 25;'
[sessions]='MATCH (c:Computer)-[:HasSession]->(u:User) WHERE u.highvalue=true OR coalesce(u.admincount,false)=true RETURN u.name AS user, c.name AS on_host ORDER BY user;'
)

ORDER=(das kerberoastable asrep unconstrained constrained dcsync path-to-da owned-adminto highvalue sessions)
if [ "$WHICH" = all ]; then
  for k in "${ORDER[@]}"; do run "$k" "${Q[$k]}"; done
elif [ -n "${Q[$WHICH]:-}" ]; then
  run "$WHICH" "${Q[$WHICH]}"
else
  c_err "Unknown query '$WHICH'. Valid: ${ORDER[*]} all"; exit 1
fi
c_ok "Done. (container: $BHCE_CONTAINER)"
