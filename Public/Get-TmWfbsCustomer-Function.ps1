Function Get-TmwfbsCustomer {
    <#
        .DESCRIPTION
            Retrieves a customer instance from Trend Micro's SMPI REST API. If no customer name or ID are provided, the command returns properties of all customers.
        .NOTES
            Author: Mike Hashemi
            V1.0.0.0 date: 3 June 2019
                - Initial release.

            https://cspi.trendmicro.com/docs/en-us/service-management-api/v28/reference/wfbss/customers/get.aspx
        .LINK
            
        .PARAMETER AccessToken
            Represents the access token used to connected to TrendMicro's SMPI REST API.
        .PARAMETER SecretKey
            Represents the secret key used to connected to TrendMicro's SMPI REST API.
        .PARAMETER Name
            Represents name of the desired customer.
        .PARAMETER Id
            Represents customer ID of the desired customer.
        .PARAMETER BaseUrl
            Represents the base URL of TrendMicro's SMPI REST API.
        .PARAMETER EventLogSource
            Default value is "TmWfbsPowerShellModule" Represents the name of the desired source, for Event Log logging.
        .PARAMETER BlockLogging
            When this switch is included, the code will write output only to the host and will not attempt to write to the Event Log.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey>

            In this example, the function will search for all customers and will return their properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Id A5D6DED5-4928-9CEF-B988-EDA3FE11FED3

            In this example, the function will search for the customer with the ID "A5D6DED5-4928-9CEF-B988-EDA3FE11FED3" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Name "Customer 1"

            In this example, the function will search for the customer with the name "Customer 1" and will return its properties.
        .EXAMPLE
            PS C:\> Get-TmwfbsComputers -AccessToken <access token> -SecretKey <SecretKey> -Name "the"

            In this example, the function will search for the customer with "the" in the name and will return their properties.
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param (
        [Parameter(Mandatory)]
        $AccessToken,

        [Parameter(Mandatory)]
        $SecretKey,

        [Parameter(Mandatory, ParameterSetName = 'CustomerName')]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'CustomerId')]
        [guid]$Id,

        $BaseUrl = "https://cspi.trendmicro.com",

        [string]$EventLogSource = 'TmWfbsPowerShellModule',

        [switch]$BlockLogging
    )

    If (-NOT($BlockLogging)) {
        $return = Add-EventLogSource -EventLogSource $EventLogSource

        If ($return -ne "Success") {
            $message = ("{0}: Unable to add event source ({1}). No logging will be performed." -f [datetime]::Now, $EventLogSource)
            Write-Host $message -ForegroundColor Yellow;

            $BlockLogging = $True
        }
    }

    $message = ("{0}: Beginning {1}." -f [datetime]::Now, $MyInvocation.MyCommand)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    $message = ("{0}: Operating in the `"{1}`" ParameterSet." -f [datetime]::Now, $PsCmdlet.ParameterSetName)
    If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

    # Initialize variables
    $epoch = [Math]::Round((New-TimeSpan -start(Get-Date -Date "1/1/1970") -end(Get-Date).ToUniversalTime()).TotalSeconds)
    $currentLoopCount = 0
    $maxLoopCount = 0
    $list = [System.Collections.Generic.List[object]]::new()
    $page = 1
    $httpMethod = "GET"
    $Name = $Name.Replace(" ", "%20")

    Function get_content_md5([String] $content) {
        $md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        $utf8 = new-object -TypeName System.Text.UTF8Encoding
        $digest = [System.Convert]::ToBase64String($md5.ComputeHash($utf8.GetBytes($content)))
        # Write-Host $digest
        return $digest
    }
    Function calc_signature([String] $secret_key, [String] $x_posix_time, [String] $request_httpMethod, [String] $request_uri, [String] $content) {
        $payload = $x_posix_time + $request_httpMethod.ToUpper() + $request_uri
        if ($content) {
            $payload += get_content_md5($content)
        }
        # Write-Host "payload: $payload"
        $hmac = New-Object System.Security.Cryptography.HMACSHA256
        $hmac.Key = [Text.Encoding]::UTF8.GetBytes($secret_key)
        $signature = [System.Convert]::ToBase64String($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($payload)))
        # Write-Host "signature: $signature"
        return $signature
    }
    Function generate_cspi_headers($httpMethod, $uri, $access_token, $secret_key, $posix_time, $content) {
        $signature = calc_signature $secret_key $posix_time $httpMethod $uri $content
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/json")
        $headers.Add("x-access-token", $access_token)
        $headers.Add("x-signature", $signature)
        $headers.Add("x-posix-time", $posix_time)
        $headers.Add("x-traceid", (New-Guid))
        return $headers
    }

    Switch ($PsCmdlet.ParameterSetName) {
        "CustomerId" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?cids=$Id"

            $message = ("{0}: Set `$resourcePath to: {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
        "CustomerName" {
            $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?q=$Name"

            $message = ("{0}: Set `$resourcePath to: {1}." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }
        }
    }

    Switch ($PsCmdlet.ParameterSetName) {
        { $_ -in ("CustomerId", "CustomerName") } {
            $message = ("{0}: Attempting to generate headers." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $headers = generate_cspi_headers $httpMethod $resourcePath $access_token $secret_key $epoch ""

            $message = ("{0}: Attempting to retrieve instance." -f [datetime]::Now, $resourcePath)
            If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

            $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers

            $response
        }
        "All" {
            While ($currentLoopCount -le $maxLoopCount) {
                $message = ("{0}: Current loop count is: {0}." -f [datetime]::Now, $currentLoopCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $resourcePath = "/SMPI/v2.8/service/wfbss/api/customers?page=$page"

                $message = ("{0}: The value of `$resourcePath is: {0}." -f [datetime]::Now, $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $message = ("{0}: Attempting to generate headers." -f [datetime]::Now, $resourcePath)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $headers = generate_cspi_headers $httpMethod $resourcePath $access_token $secret_key $epoch ""

                $message = ("{0}: Attempting to retrieve page {1} of instances." -f [datetime]::Now, $page)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $response = Invoke-RestMethod -Uri "$BaseUrl$resourcePath" -Method $httpMethod -Headers $headers

                $list.AddRange($response.customers)

                $maxLoopCount = $response.paging.total / $response.paging.limit

                $message = ("{0}: The value of `$maxLoopCount is: {1}." -f [datetime]::Now, $maxLoopCount)
                If (($BlockLogging) -AND ($PSBoundParameters['Verbose'])) { Write-Verbose $message } ElseIf ($PSBoundParameters['Verbose']) { Write-Verbose $message; Write-EventLog -LogName Application -Source $EventLogSource -EntryType Information -Message $message -EventId 5417 }

                $currentLoopCount++
                $page++
            }

            $list
        }
    }
} #1.0.0.0