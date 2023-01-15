rule h3k_tinyfilemanager_login {
    meta:
        description = "H3K Tiny File Manager login"
        author = "Josh Stroschein josh@m9cyber.com"
        date = "2023-01-15"

    strings:
        $s1 = "Tiny File Manager</title>" nocase
        $s2 = "form-signin" nocase
        $s3 = "fm_usr" nocase
        $s4 = "fm_pwd" nocase
        $s5 = ".fm-login-page" nocase

    condition:
        all of them
}
