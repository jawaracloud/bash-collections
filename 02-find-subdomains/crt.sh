crstsh(){
  curl -s "https://crt.sh/?q=%25.${1}&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httpx -sc -title -fr | tee -a ${1}.txt
}
