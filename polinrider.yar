rule polinrider_payload {
    meta:
        description = "Detects PolinRider shuffle-cipher JS payloads — both rmcej%otb% (v1) and Cot%3t=shtP (v2) variants"
        author = "OpenSourceMalware.com"
        date = "2026-04-10"
        severity = "high"

    strings:
        // Original variant (rmcej%otb%)
        $marker_v1   = "rmcej%otb%"
        $seed1_v1    = "2857687"
        $seed2_v1    = "2667686"
        $varname_v1  = "_$_1e42"
        $global_bang = "global['!']"

        // New variant (Cot%3t=shtP)
        $marker_v2   = "Cot%3t=shtP"
        $seed1_v2    = "1111436"
        $seed2_v2    = "3896884"
        $varname_v2  = "MDy"
        $global_V    = "global['_V']"

        // Common across variants
        $global_r    = "global['r'] = require"
        $global_m    = "global['m'] = module"

    condition:
        any of ($marker_*) or
        ($global_bang and ($seed1_v1 or $varname_v1)) or
        ($global_V    and ($seed1_v2 or $varname_v2)) or
        ($global_r and $global_m and (any of ($seed1_*)))
}
