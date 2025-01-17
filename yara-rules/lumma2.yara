rule Lumma2
{
    meta:
        author = "fabamatic"
        description = "Lumma2 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "LummaC2, Build:" ascii
        $x2 = "LID (Lumma ID):" ascii
        $x3 = "- Screen resolution:" ascii
        $x4 = "- HWID:" ascii
        $x5 = "- OS Version:" ascii

    condition:
        all of them
}