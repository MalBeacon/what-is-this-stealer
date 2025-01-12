rule Phemedrone
{
    meta:
        author = "MalBeacon"
        description = "Phemedrone system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "----- Geolocation Data -----" ascii
        $x2 = "----- Hardware Info -----" ascii
        $x3 = "----- Report Contents -----" ascii
        $x4 = "----- Miscellaneous -----" ascii
        $x5 = "Clipboard text:" ascii
        $x6 = "Antivirus products:" ascii

    condition:
        all of them
}