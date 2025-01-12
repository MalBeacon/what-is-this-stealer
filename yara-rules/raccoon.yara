rule Raccoon
{
    meta:
        author = "MalBeacon"
        description = "Raccoon system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "System Information:" ascii
        $x2 = "Bot_ID:" ascii
        $x3 = "Launched at:" ascii
        $x4 = "Build compile date:" ascii
        $x5 = "Installed Apps:" ascii
        $x6 = "-------------" ascii

    condition:
        all of them
}