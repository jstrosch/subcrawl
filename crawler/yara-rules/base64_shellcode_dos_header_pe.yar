rule base64_shellcode_dos_header_pe
{
  meta:
    description = "Detects base64 encoded PE files, often used with Powershell, that contains magic bytes that allow for the image_dos_header to contain shellcode.."
    author = "josh@m9cyber.com"
    date = "2023-01-23"
 strings:
    $mz_header = /(TVpFUu|uUFpVT|TVpSRQ|QRSpTV|TVpBUg|gUBpVT)/
    $this_program = /(VGhpcyBwcm9ncmFt|tFmcn9mcwBycphGV)/
    $null_bytes = "AAAAA"
 condition:
    $mz_header at 0 and $this_program and #null_bytes > 2
}
