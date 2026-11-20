# usage: bash ../decide.sh <id> approve|deny
python -I -c "
import json,sys
d=json.load(open('decisions.json')); d[sys.argv[1]]=sys.argv[2]; json.dump(d,open('decisions.json','w'),indent=2); print('decided',sys.argv[1],sys.argv[2])" "$1" "$2"
