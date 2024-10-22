<?xml version="1.0" encoding="utf-16" ?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <xsl:comment>
    Lists findings by severity and categorizes low findings without a CVSS score as Informational.
	<eric.gragsone@erisresearch.org>
  </xsl:comment>
  <xsl:output method="html" indent="yes" />
  <xsl:key name="pluginID" match="Report/ReportHost/*" use="concat(../../ReportName,pluginID)"></xsl:key>
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
    <th align="left" class="severity_header_label">Risk_Factor</th>
    <th align="left" class="description_header_label">Description</th>
    <th align="left" class="solution_header_label">Solution</th>
    <th align="left" class="reference_header_label">Reference</th>
    <th align="left" class="protocol_header_label">Protocol</th>
    <th align="left" class="hosts_header_label">Host_List</th>
  </thead>

  <tbody>
    <xsl:for-each select="key('vulnsFound','3')">
      <xsl:sort select="count(key('vulnHost',@pluginID))" data-type="number" order="descending" />
      <xsl:if test="generate-id() = generate-id(key('pluginsFound',@pluginID)[1])" >
    <tr>
      <td valign="top" class="sev_high">
        <xsl:value-of select="@pluginName"/>
      </td>

      <td valign="top">High</td>

      <td valign="top">
        <xsl:value-of select="./description"/>
      </td>

      <td valign="top">
        <xsl:value-of select="./solution"/>
      </td>

      <td valign="top">
        <xsl:for-each select="./see_also">
          <xsl:value-of select="."/>&#160;
        </xsl:for-each>
      </td>

      <td valign="top">
        <xsl:value-of select="@protocol"/>
      </td>

      <td valign="top">
        <xsl:for-each select="key('vulnHost',@pluginID)">
        <xsl:sort select="../HostProperties/tag[@name='host-ip']" />
          <xsl:value-of select="../HostProperties/tag[@name='host-ip']" />:<xsl:value-of select="@port"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
      </xsl:if>
    </xsl:for-each>

    <xsl:for-each select="key('vulnsFound','2')">
      <xsl:sort select="count(key('vulnHost',@pluginID))" data-type="number" order="descending" />
      <xsl:if test="generate-id() = generate-id(key('pluginsFound',@pluginID)[1])" >
    <tr>
      <td valign="top" class="sev_high">
        <xsl:value-of select="@pluginName"/>
      </td>

      <td valign="top">Medium</td>

      <td valign="top">
        <xsl:value-of select="./description"/>
      </td>

      <td valign="top">
        <xsl:value-of select="./solution"/>
      </td>

      <td valign="top">
        <xsl:for-each select="./see_also">
          <xsl:value-of select="."/>&#160;
        </xsl:for-each>
      </td>

      <td valign="top">
        <xsl:value-of select="@protocol"/>
      </td>

      <td valign="top">
        <xsl:for-each select="key('vulnHost',@pluginID)">
        <xsl:sort select="../HostProperties/tag[@name='host-ip']" />
          <xsl:value-of select="../HostProperties/tag[@name='host-ip']" />:<xsl:value-of select="@port"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
      </xsl:if>
    </xsl:for-each>

    <xsl:for-each select="key('vulnsFound','1')">
      <xsl:sort select="count(key('vulnHost',@pluginID))" data-type="number" order="descending" />
      <xsl:if test="generate-id() = generate-id(key('pluginsFound',@pluginID)[1])" >
	  <xsl:if test="./cvss_base_score">
    <tr>
      <td valign="top" class="sev_high">
        <xsl:value-of select="@pluginName"/>
      </td>

      <td valign="top">Low</td>

      <td valign="top">
        <xsl:value-of select="./description"/>
      </td>

      <td valign="top">
        <xsl:value-of select="./solution"/>
      </td>

      <td valign="top">
        <xsl:for-each select="./see_also">
          <xsl:value-of select="."/>&#160;
        </xsl:for-each>
      </td>

      <td valign="top">
        <xsl:value-of select="@protocol"/>
      </td>

      <td valign="top">
        <xsl:for-each select="key('vulnHost',@pluginID)">
        <xsl:sort select="../HostProperties/tag[@name='host-ip']" />
          <xsl:value-of select="../HostProperties/tag[@name='host-ip']" />:<xsl:value-of select="@port"/>&#160;
        </xsl:for-each>
      </td>

    </tr>
	  </xsl:if>
      </xsl:if>
    </xsl:for-each>
	<xsl:for-each select="key('vulnsFound','1')">
      <xsl:sort select="count(key('vulnHost',@pluginID))" data-type="number" order="descending" />
      <xsl:if test="generate-id() = generate-id(key('pluginsFound',@pluginID)[1])" >
	  <xsl:choose>
		<xsl:when test="./cvss_base_score">
                </xsl:when>
                <xsl:otherwise>
    <tr>
      <td valign="top" class="sev_high">
        <xsl:value-of select="@pluginName"/>
      </td>

      <td valign="top">Informational</td>

      <td valign="top">
        <xsl:value-of select="./description"/>
      </td>

      <td valign="top">
        <xsl:value-of select="./solution"/>
      </td>

      <td valign="top">
        <xsl:for-each select="./see_also">
          <xsl:value-of select="."/>&#160;
        </xsl:for-each>
      </td>

      <td valign="top">
        <xsl:value-of select="@protocol"/>
      </td>

      <td valign="top">
        <xsl:for-each select="key('vulnHost',@pluginID)">
        <xsl:sort select="../HostProperties/tag[@name='host-ip']" />
          <xsl:value-of select="../HostProperties/tag[@name='host-ip']" />:<xsl:value-of select="@port"/>&#160;
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
</xsl:stylesheet>
