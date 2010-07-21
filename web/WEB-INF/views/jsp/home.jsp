<%@ include file="/WEB-INF/views/jsp/common/include.jsp" %>

<tiles:insertDefinition name="center-layout" >
	
	<tiles:putAttribute type="string" name="title" value="Home Page" />
			
	<!-- body -->
	<tiles:putAttribute name="body">
		Spring Project Home page
	</tiles:putAttribute>

</tiles:insertDefinition>