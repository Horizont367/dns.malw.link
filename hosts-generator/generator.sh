#!/bin/bash

mapfile -t IPS < "./input_sni_proxy_ips.txt"

echo '### dns.malw.link: hosts file' > ../hosts
echo -e "# Последнее обновление: $(date '+%d %B %Y')\n" >> ../hosts

cat ../lists/hosts.txt >> ../hosts
echo >> ../hosts

jq -c '.[]' input_domains.json | while read -r section; do
    sec_name=$(echo "$section" | jq -r '.section')
    force_ip=$(echo "$section" | jq -r '.force_ip // ""')
    echo -e "\n# $sec_name" >> ../hosts

    for domain in $(echo "$section" | jq -r '.domains | if type=="array" then .[] else . end'); do
        if [[ -n "$force_ip" ]]; then
            echo "Используется $force_ip для $domain"
            echo "$force_ip $domain" >> ../hosts
        else
            found=0
            for ip in "${IPS[@]}"; do
                echo "Проверка $domain на $ip..."
                if curl -s -o /dev/null -m 15 "https://$domain" --connect-to "::$ip"; then
                    echo "$ip $domain" >> ../hosts
                    found=1
                    break
                fi
            done

            if [[ $found -eq 0 ]]; then
                echo "!!! Не найден рабочий IP для $domain"
            fi
        fi
    done
done

echo -e '\n# Блокировка' >> ../hosts
sed 's/^/0.0.0.0 /' ../lists/garbage.txt >> ../hosts

echo -e "\n\n### dns.malw.link: end hosts file" >> ../hosts

default_ip=$(grep -v ":" ../dns-server/sni_proxy_ips.txt | head -n1)

declare -A seen_domains
> ../adguard.txt

while read -r ip domain; do
    if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
        echo "|$domain^\$dnsrewrite=$ip" >> ../adguard.txt
        seen_domains["$domain"]=1
    fi
done < ../lists/hosts.txt

while read -r section; do
    force_ip=$(echo "$section" | jq -r '.force_ip // ""')
    while read -r domain; do
        if [[ -z "${seen_domains[$domain]}" ]]; then
            if [[ -n "$force_ip" ]]; then
                echo "|$domain^\$dnsrewrite=$force_ip" >> ../adguard.txt
                seen_domains["$domain"]=1
            else
                found=0
                for ip in "${IPS[@]}"; do
                    echo "Проверка $domain на $ip (AdGuard)..."
                    if curl -s -o /dev/null -m 15 "https://$domain" --connect-to "::$ip"; then
                        echo "|$domain^\$dnsrewrite=$ip" >> ../adguard.txt
                        seen_domains["$domain"]=1
                        found=1
                        break
                    fi
                done

                if [[ $found -eq 0 ]]; then
                    echo "!!! Не найден рабочий IP для $domain"
                fi
            fi
        fi
    done < <(echo "$section" | jq -r '.domains | if type=="array" then .[] else . end')
done < <(jq -c '.[]' input_domains.json)

while read -r domain; do
    if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
        echo "||$domain^\$dnsrewrite=$default_ip" >> ../adguard.txt
        seen_domains["$domain"]=1
    fi
done < ../lists/domains_with_subdomains.txt

echo >> ../adguard.txt

while read -r domain; do
    if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
        found=0
        for ip in "${IPS[@]}"; do
            echo "Проверка $domain на $ip (AdGuard)..."
            if curl -s -o /dev/null -m 15 "https://$domain" --connect-to "::$ip"; then
                echo "|$domain^\$dnsrewrite=$ip" >> ../adguard.txt
                seen_domains["$domain"]=1
                found=1
                break
            fi
        done

        if [[ $found -eq 0 ]]; then
            echo "!!! Не найден рабочий IP для $domain"
        fi
    fi
done < ../lists/domains.txt

while read -r domain; do
    if [[ -n "$domain" && -z "${seen_domains[$domain]}" ]]; then
        echo "|$domain^\$dnsrewrite=0.0.0.0" >> ../adguard.txt
        seen_domains["$domain"]=1
    fi
done < ../lists/garbage.txt