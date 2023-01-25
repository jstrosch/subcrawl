rule agenttesla_panel_login
{
  meta:
    description = "AgentTesla panel login page"
    author = "josh@m9cyber.com"
    date = "2022-03-10"
 strings:
    $title = "web panel | login</title>" nocase
    $form_action = "action=\"login.php\"" nocase
    $pass = "name=\"password\"" nocase
    $user = "name=\"username\"" nocase

 condition:
    all of them
}

rule agenttesla_panel_login_2
{
  meta:
    description = "Origin (AgentTesla) Webpanel"
    author = "josh@m9cyber.com"
    date = "2022-02-21"
 strings:
    $title = "Login</title>"
    $form = "action=\"login.php\""
    $signin = "box-title m-b-20\">Sign In"
    $style = "margin: auto;margin-top:100px;}"
 condition:
    all of them
}
