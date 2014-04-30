<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:c="http://check.sourceforge.net/ns">
<xsl:output method="text" indent="no"/>
<xsl:strip-space elements="c:message"/>

<xsl:template match="/c:testsuites">

    <xsl:text>:test-global-result: </xsl:text>
    <xsl:text>Checks: </xsl:text><xsl:value-of select="count(c:suite/c:test)"/>
    <xsl:text>, PASS: </xsl:text><xsl:value-of select="count(c:suite/c:test[@result = 'success'])"/>
    <xsl:text>, FAIL: </xsl:text><xsl:value-of select="count(c:suite/c:test[@result = 'failure'])"/>
    <xsl:text>, ERROR: </xsl:text><xsl:value-of select="count(c:suite/c:test[@result != 'success'][@result != 'failure'])"/>
    <xsl:text>
</xsl:text>

    <xsl:choose>
        <xsl:when test="c:suite/c:test[@result != 'success']">
        <xsl:text>:global-log-copy: yes
:recheck: yes
</xsl:text>
        </xsl:when>
        <xsl:otherwise>
        <xsl:text>:global-log-copy: no
:recheck: no
</xsl:text>
        </xsl:otherwise>
    </xsl:choose>

    <xsl:for-each select="c:suite/c:test">
        <xsl:text>:test-result: </xsl:text>
        <xsl:choose>
            <xsl:when test="@result = 'success'">
                <xsl:text>PASS </xsl:text>
            </xsl:when>
            <xsl:when test="@result = 'failure'">
                <xsl:text>FAIL </xsl:text>
            </xsl:when>
            <xsl:otherwise>
                <xsl:text>ERROR </xsl:text>
            </xsl:otherwise>
        </xsl:choose>
        <xsl:value-of select="c:fn"/>
        <xsl:text>:</xsl:text>
        <xsl:value-of select="c:description"/>
        <xsl:text>:</xsl:text>
        <xsl:value-of select="c:id"/>
        <xsl:text>:</xsl:text>
        <xsl:value-of select="c:iteration"/>
        <xsl:text>:</xsl:text>
        <xsl:value-of select="c:duration"/>
        <xsl:text> </xsl:text>
        <xsl:value-of select="c:message"/>
        <xsl:text>
</xsl:text>
    </xsl:for-each>

</xsl:template>
</xsl:stylesheet>

