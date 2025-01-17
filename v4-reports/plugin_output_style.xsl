<?xml version="1.0" encoding="utf-16" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:comment>
    Some plugins save their output which can provide useful context.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method="html" indent="yes" />
  <xsl:key name="vulnsFound" match="ReportItem" use="@severity"/>
  <xsl:key name="pluginsFound" match="ReportItem" use="@pluginID"/>
  <xsl:key name="vulnHost" match="ReportItem" use="@pluginID"/>
  <xsl:template name="support_formats"><![CDATA[html]]></xsl:template>
  <xsl:template match="/">
    <html>
	<body>
<table border="0" cellpadding="1" cellspacing="0" width="100%">
  <thead class="port_header">
    <th align="left" class="finding_header_label">Finding_Name</th>
    <th align="left" class="finding_header_label">Plugin ID</th>
    <th align="left" class="severity_header_label">Host_List</th>
    <th align="left" class="description_header_label">Output</th>
  </thead>

  <tbody>
	
	<xsl:for-each select="//plugin_output">
    <tr>
      <td valign="top" class="sev_high">
        <xsl:value-of select="../@pluginName"/>
      </td>

      <td valign="top" class="sev_high">
        <xsl:value-of select="../@pluginID"/>
      </td>

      <td valign="top">
          <xsl:value-of select="../../HostProperties/tag[@name='host-ip']" />:<xsl:value-of select="../@port"/>&#160;
      </td>
	  
      <td valign="top">
	  <xsl:value-of select="."/>
      </td>
    </tr>
    </xsl:for-each>
	
  </tbody>
</table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>
