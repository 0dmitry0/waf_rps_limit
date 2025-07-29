when RULE_INIT {
    set json_response_blocked "{\"status\":\"error\"}"
    set json_response_permited "{\"status\":\"good\"}"
    set rps_value 1
}

when HTTP_REQUEST {
    set client_ip [IP::client_addr]
    
    if {[string tolower [HTTP::uri]] starts_with "/test"} {
    
        set last_request [table lookup -subtable "rate_limit_$client_ip" "last_time_request"]
        
        table set -subtable "rate_limit_$client_ip" "last_time_request" [clock seconds] 120
        
        log local0.error "Last request time for $client_ip: $last_request"
        
        if {$last_request ne "" && [clock seconds] - $last_request < $rps_value} {
            log local0.error "Rate limit exceeded for $client_ip"
            HTTP::respond 200 content $json_response_blocked "Content-Type" "application/json"
            return
        } else {
            HTTP::respond 200 content $json_response_permited "Content-Type" "application/json"
            return
        }
    }
}
