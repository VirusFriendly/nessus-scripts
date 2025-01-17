<?xml version="1.0" encoding="utf-16" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:comment>
    Lists hosts by ip and displays their OS and Device type.
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
        <th>Host Name</th>
        <th>Operating System</th>
	<th>OS Confidence</th>
	<th>OS Method</th>
        <th>Device Type</th>
	<th>Device Type Confidence</th>
      </thead>
    <xsl:for-each select="//ReportHost">
    <xsl:sort select="@name" />
      <xsl:variable name="os" select="substring-after(./ReportItem[@pluginID='11936']/plugin_output,'Remote operating system : ')"/>
      <xsl:variable name="oscon" select="substring-after($os, 'Confidence Level : ')"/>
      <xsl:variable name="dt" select="substring-after(./ReportItem[@pluginID='54615']/plugin_output,'Remote device type : ')"/>
      <tr>
        <td><xsl:value-of select="./HostProperties/tag[@name='host-ip']"/></td>
        <td><xsl:value-of select="./HostProperties/tag[@name='host-fqdn']"/></td>
        <td><xsl:value-of select="substring-before($os, 'Confidence Level : ')"/></td>
        <td><xsl:value-of select="substring-before($oscon, 'Method : ')"/></td>
        <td><xsl:value-of select="substring-after($oscon, 'Method : ')"/></td>
        <td><xsl:value-of select="substring-before($dt, 'Confidence level : ')"/></td>
        <td><xsl:value-of select="substring-after($dt, 'Confidence level : ')"/></td>
      </tr>
    </xsl:for-each>
    </table>
  </body>
</html>
</xsl:template>
</xsl:stylesheet>
