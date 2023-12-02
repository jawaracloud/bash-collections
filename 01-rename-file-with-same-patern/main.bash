patern="$1"
extentions="$2"
for old_name in $patern*.$extentions; do
    new_name=$(echo "$old_name"| sed 's/$patern//g')
    mv "$old_name" "$new_name"
done