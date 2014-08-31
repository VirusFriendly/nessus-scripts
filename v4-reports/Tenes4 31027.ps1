#
# Tenes v4.3.1027
#
# Create a report directory
# Movie this file and all your nessus reports (as .nessus) into that directory
# Right click on this file and select run with PowerShell
# This script grabs all the nessus_report (.nessus) files in the current directory
# and spits out four html files.
#
# nessus_report.html - lists findings by severity and categorizes low findings
#     without a CVSS score as Informational.
#
# hosts_report.html - lists hosts by ip and displays their OS and Device type.
#
# unchecked_ports.html - lists the ports which Nessus didn't scan. Most people
#     don't bother checking these ports, but I'm never limited by my tools.
#
# plugin_output.html - Some plugins save their output which can provide useful
#     context.
#
# Note: If it doesn't run AND you trust this script, you may want to open up
#     powershell as administrator and run the following command:
#
#     set-ExecutionPolicy Unrestricted
#
#     Read the prompt and think about it carefully, as it'll effect not only
#     this script but any other malicious script you may currently or in the
#     future have on your computer.
#
# <eric.gragsone@erisresearch.org>
#
###############################################################################

$aggroxml='nessus_report.dat'
$reportxsl='report_style.xsl'
$reportoutput='nessus_report.html'
$hostsxsl='hosts_style.xsl'
$hostsoutput='hosts_report.html'
$portxsl='port_style.xsl'
$portoutput='unchecked_ports.html'
$outputxsl='plugin_output_style.xsl'
$outputoutput='plugin_output_spreadsheet.html'

$xslt = New-Object System.Xml.Xsl.XslCompiledTransform;

function FilterNessus {
  param(
    [Parameter(ValueFromPipeline=$true)]
    $Incoming
  )
  
  process {
    if (($incoming -like '*NessusClientData_v2>') -or ($incoming -like '*xml version*')) {
    } else {
      echo $incoming
    }
  }
}

echo 'Creating translation files'
echo "<?xml version=`"1.0`" encoding=`"utf-16`" ?>
<xsl:stylesheet xmlns:xsl=`"http://www.w3.org/1999/XSL/Transform`" version=`"1.0`">
  <xsl:comment>
    Lists findings by severity and categorizes low findings without a CVSS score as Informational.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method=`"html`" indent=`"yes`" />
  <xsl:key name=`"pluginID`" match=`"Report/ReportHost/*`" use=`"concat(../../ReportName,pluginID)`"></xsl:key>
  <xsl:key name=`"vulnsFound`" match=`"ReportItem`" use=`"@severity`"/>
  <xsl:key name=`"pluginsFound`" match=`"ReportItem`" use=`"@pluginID`"/>
  <xsl:key name=`"vulnHost`" match=`"ReportItem`" use=`"@pluginID`"/>
  <xsl:template name=`"support_formats`"><![CDATA[html]]></xsl:template>
  <xsl:template match=`"/`">
    <html>
	<body>
<table border=`"0`" cellpadding=`"1`" cellspacing=`"0`" width=`"100%`">
  <thead class=`"port_header`">
    <th align=`"left`" class=`"finding_header_label`">Finding_Name</th>
    <th align=`"left`" class=`"severity_header_label`">Risk_Factor</th>
    <th align=`"left`" class=`"description_header_label`">Description</th>
    <th align=`"left`" class=`"solution_header_label`">Solution</th>
    <th align=`"left`" class=`"reference_header_label`">Reference</th>
    <th align=`"left`" class=`"protocol_header_label`">Protocol</th>
    <th align=`"left`" class=`"hosts_header_label`">Host_List</th>
  </thead>

  <tbody>
    <xsl:for-each select=`"key('vulnsFound','3')`">
      <xsl:sort select=`"count(key('vulnHost',@pluginID))`" data-type=`"number`" order=`"descending`" />
      <xsl:if test=`"generate-id() = generate-id(key('pluginsFound',@pluginID)[1])`" >
    <tr>
      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"@pluginName`"/>
      </td>

      <td valign=`"top`">High</td>

      <td valign=`"top`">
        <xsl:value-of select=`"./description`"/>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"./solution`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"./see_also`">
          <xsl:value-of select=`".`"/>&#160;
        </xsl:for-each>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"@protocol`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"key('vulnHost',@pluginID)`">
        <xsl:sort select=`"../HostProperties/tag[@name='host-ip']`" />
          <xsl:value-of select=`"../HostProperties/tag[@name='host-ip']`" />:<xsl:value-of select=`"@port`"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
      </xsl:if>
    </xsl:for-each>

    <xsl:for-each select=`"key('vulnsFound','2')`">
      <xsl:sort select=`"count(key('vulnHost',@pluginID))`" data-type=`"number`" order=`"descending`" />
      <xsl:if test=`"generate-id() = generate-id(key('pluginsFound',@pluginID)[1])`" >
    <tr>
      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"@pluginName`"/>
      </td>

      <td valign=`"top`">Medium</td>

      <td valign=`"top`">
        <xsl:value-of select=`"./description`"/>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"./solution`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"./see_also`">
          <xsl:value-of select=`".`"/>&#160;
        </xsl:for-each>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"@protocol`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"key('vulnHost',@pluginID)`">
        <xsl:sort select=`"../HostProperties/tag[@name='host-ip']`" />
          <xsl:value-of select=`"../HostProperties/tag[@name='host-ip']`" />:<xsl:value-of select=`"@port`"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
      </xsl:if>
    </xsl:for-each>

    <xsl:for-each select=`"key('vulnsFound','1')`">
      <xsl:sort select=`"count(key('vulnHost',@pluginID))`" data-type=`"number`" order=`"descending`" />
      <xsl:if test=`"generate-id() = generate-id(key('pluginsFound',@pluginID)[1])`" >
	  <xsl:if test=`"./cvss_base_score`">
    <tr>
      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"@pluginName`"/>
      </td>

      <td valign=`"top`">Low</td>

      <td valign=`"top`">
        <xsl:value-of select=`"./description`"/>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"./solution`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"./see_also`">
          <xsl:value-of select=`".`"/>&#160;
        </xsl:for-each>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"@protocol`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"key('vulnHost',@pluginID)`">
        <xsl:sort select=`"../HostProperties/tag[@name='host-ip']`" />
          <xsl:value-of select=`"../HostProperties/tag[@name='host-ip']`" />:<xsl:value-of select=`"@port`"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
	  </xsl:if>
      </xsl:if>
    </xsl:for-each>
	<xsl:for-each select=`"key('vulnsFound','1')`">
      <xsl:sort select=`"count(key('vulnHost',@pluginID))`" data-type=`"number`" order=`"descending`" />
      <xsl:if test=`"generate-id() = generate-id(key('pluginsFound',@pluginID)[1])`" >
	  <xsl:choose>
		<xsl:when test=`"./cvss_base_score`">
                </xsl:when>
                <xsl:otherwise>
    <tr>
      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"@pluginName`"/>
      </td>

      <td valign=`"top`">Informational</td>

      <td valign=`"top`">
        <xsl:value-of select=`"./description`"/>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"./solution`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"./see_also`">
          <xsl:value-of select=`".`"/>&#160;
        </xsl:for-each>
      </td>

      <td valign=`"top`">
        <xsl:value-of select=`"@protocol`"/>
      </td>

      <td valign=`"top`">
        <xsl:for-each select=`"key('vulnHost',@pluginID)`">
        <xsl:sort select=`"../HostProperties/tag[@name='host-ip']`" />
          <xsl:value-of select=`"../HostProperties/tag[@name='host-ip']`" />:<xsl:value-of select=`"@port`"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
                </xsl:otherwise>
	  </xsl:choose>
      </xsl:if>
    </xsl:for-each>
  </tbody>
</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>" > $reportxsl

echo "<?xml version=`"1.0`" encoding=`"utf-16`" ?>
<xsl:stylesheet xmlns:xsl=`"http://www.w3.org/1999/XSL/Transform`" version=`"1.0`">
  <xsl:comment>
    Lists hosts by ip and displays their OS and Device type.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method=`"html`" indent=`"yes`" />
  <xsl:template name=`"support_formats`"><![CDATA[html]]></xsl:template>
  <xsl:template match=`"/`">
<html>
  <body>
    <table>
      <thead>
        <th>IP Address</th>
        <th>Host Name</th>
        <th>Operating System</th>
	<th>OS Confidence</th>
	<th>OS Method</th>
        <th>Device Type</th>
	<th>Device Type Confidence</th>
      </thead>
    <xsl:for-each select=`"//ReportHost`">
    <xsl:sort select=`"@name`" />
      <xsl:variable name=`"os`" select=`"substring-after(./ReportItem[@pluginID='11936']/plugin_output,'Remote operating system : ')`"/>
      <xsl:variable name=`"oscon`" select=`"substring-after(`$os, 'Confidence Level : ')`"/>
      <xsl:variable name=`"dt`" select=`"substring-after(./ReportItem[@pluginID='54615']/plugin_output,'Remote device type : ')`"/>
      <tr>
        <td><xsl:value-of select=`"./HostProperties/tag[@name='host-ip']`"/></td>
        <td><xsl:value-of select=`"./HostProperties/tag[@name='host-fqdn']`"/></td>
        <td><xsl:value-of select=`"substring-before(`$os, 'Confidence Level : ')`"/></td>
        <td><xsl:value-of select=`"substring-before(`$oscon, 'Method : ')`"/></td>
        <td><xsl:value-of select=`"substring-after(`$oscon, 'Method : ')`"/></td>
        <td><xsl:value-of select=`"substring-before(`$dt, 'Confidence level : ')`"/></td>
        <td><xsl:value-of select=`"substring-after(`$dt, 'Confidence level : ')`"/></td>
      </tr>
    </xsl:for-each>
    </table>
  </body>
</html>
</xsl:template>
</xsl:stylesheet>" > $hostsxsl

echo "<?xml version=`"1.0`" encoding=`"utf-16`" ?>
<xsl:stylesheet xmlns:xsl=`"http://www.w3.org/1999/XSL/Transform`" version=`"1.0`">
  <xsl:comment>
    Lists the ports which Nessus didn't scan.
    Most people don't bother checking these ports, but I'm never limited by my tools.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method=`"html`" indent=`"yes`" />
  <xsl:template name=`"support_formats`"><![CDATA[html]]></xsl:template>
  <xsl:template match=`"/`">
<html>
  <body>
  
    <table>
      <thead>
        <th>IP Address</th>
        <th>Port/Protocol</th>
	<th>Service Name</th>
        <th>Banner</th>
      </thead>
    <xsl:for-each select=`"//ReportItem[@pluginID='11154']`">
	  <tr>
	    <td><xsl:value-of select=`"../HostProperties/tag[@name='host-ip']`"/></td>
	    <td><xsl:value-of select=`"@port`" />/<xsl:value-of select=`"@protocol`" /></td>
	    <td><xsl:value-of select=`"@svc_name`" /></td>
            <td><xsl:value-of select=`"substring-after(./plugin_output, 'Type')`" /></td>
	  </tr>
  </xsl:for-each>
    </table>
  </body>
</html>
</xsl:template>
</xsl:stylesheet>" > $portxsl

echo "<?xml version=`"1.0`" encoding=`"utf-16`" ?>
<xsl:stylesheet xmlns:xsl=`"http://www.w3.org/1999/XSL/Transform`" version=`"1.0`">
  <xsl:comment>
    Some plugins save their output which can provide useful context.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method=`"html`" indent=`"yes`" />
  <xsl:key name=`"vulnsFound`" match=`"ReportItem`" use=`"@severity`"/>
  <xsl:key name=`"pluginsFound`" match=`"ReportItem`" use=`"@pluginID`"/>
  <xsl:key name=`"vulnHost`" match=`"ReportItem`" use=`"@pluginID`"/>
  <xsl:template name=`"support_formats`"><![CDATA[html]]></xsl:template>
  <xsl:template match=`"/`">
    <html>
	<body>
<table border=`"0`" cellpadding=`"1`" cellspacing=`"0`" width=`"100%`">
  <thead class=`"port_header`">
    <th align=`"left`" class=`"finding_header_label`">Finding_Name</th>
    <th align=`"left`" class=`"finding_header_label`">Plugin ID</th>
    <th align=`"left`" class=`"severity_header_label`">Host_List</th>
    <th align=`"left`" class=`"description_header_label`">Output</th>
  </thead>

  <tbody>
	
	<xsl:for-each select=`"//plugin_output`">
    <tr>
      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"../@pluginName`"/>
      </td>

      <td valign=`"top`" class=`"sev_high`">
        <xsl:value-of select=`"../@pluginID`"/>
      </td>

      <td valign=`"top`">
          <xsl:value-of select=`"../../HostProperties/tag[@name='host-ip']`" />:<xsl:value-of select=`"../@port`"/>&#160;
      </td>
	  
      <td valign=`"top`">
	  <xsl:value-of select=`".`"/>
      </td>
    </tr>
    </xsl:for-each>
	
  </tbody>
</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>" > $outputxsl

echo 'Collecting Nessus Reports'
echo "<?xml version=`"1.0`"?>
<?xml-stylesheet type=`"text/xsl`" href=`"$xslFilePath`"?>
<NessusClientData_v2>" > $aggroxml
cat nessus_report*.nessus | FilterNessus >> $aggroxml
echo '</NessusClientData_v2>' >> $aggroxml

echo 'Generating Summary'
$xslt.Load($reportxsl);
$xslt.Transform($aggroxml, $reportoutput);

echo 'Generating Hosts File'
$xslt.Load($hostsxsl);
$xslt.Transform($aggroxml, $hostsoutput);

echo 'Generating Unchecked Ports File'
$xslt.Load($portxsl);
$xslt.Transform($aggroxml, $portoutput);

echo 'Generating Plugin Output File'
$xslt.Load($outputxsl);
$xslt.Transform($aggroxml, $outputoutput);