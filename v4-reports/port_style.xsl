<?xml version="1.0" encoding="utf-16" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:comment>
    Lists the ports which Nessus didn't scan.
    Most people don't bother checking these ports, but I'm never limited by my tools.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method="html" indent="yes" />
  <xsl:template name="support_formats"><![CDATA[html]]></xsl:template>
  <xsl:template match="/">
<html>
  <body>
  
    <table>
      <thead>
        <th>IP Address</th>
        <th>Port/Protocol</th>
	<th>Service Name</th>
        <th>Banner</th>
      </thead>
    <xsl:for-each select="//ReportItem[@pluginID='11154']">
	  <tr>
	    <td><xsl:value-of select="../HostProperties/tag[@name='host-ip']"/></td>
	    <td><xsl:value-of select="@port" />/<xsl:value-of select="@protocol" /></td>
	    <td><xsl:value-of select="@svc_name" /></td>
            <td><xsl:value-of select="substring-after(./plugin_output, 'Type')" /></td>
	  </tr>
  </xsl:for-each>
    </table>
  </body>
</html>
</xsl:template>
</xsl:stylesheet>
