package esg.security.policy.service.impl;

import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import esg.security.policy.service.api.PolicyAttribute;
import esg.security.policy.service.api.PolicyService;

/**
 * Test class for {@link PolicyServiceLocalXmlImpl}.
 * 
 * @author luca.cinquini
 */
public class PolicyServiceLocalXmlImplTest {
	
	private static String XMLFILE = "esg/security/policy/service/data/ESGFpolicies.xml";
	
	private PolicyService service;
	
	private final String ATT_TYPE_ANY = "ANY";
	private final String ATT_TYPE_NONE = "NONE";
	
	private final String ATT_TYPE1 = "CMIP5 Research";
	private final String ATT_TYPE2 = "CMIP5 Commercial";
	private final String ATT_TYPE3 = "AIRS";
	private final String ATT_TYPE4 = "MLS";
	
	private final String ATT_VALUEA = "User";
	private final String ATT_VALUEB = "Admin";
	
	@Before
	public void setup() throws Exception {
		service = new PolicyServiceLocalXmlImpl(XMLFILE);
		//((PolicyServiceLocalXmlImpl)service).print();
	}
	
	
	@Test
	public void testGetRequiredAttributes() throws Exception {
		
		testPolicy("cmip5", "Read", new String[] { ATT_TYPE1, ATT_TYPE2 }, new String[] { ATT_VALUEA,  ATT_VALUEA  } );
		testPolicy("cmip5.mymodel", "Read", new String[] { ATT_TYPE1, ATT_TYPE2 }, new String[] { ATT_VALUEA,  ATT_VALUEA  } );
		testPolicy("prefix.cmip5.mymodel", "Read", new String[] {}, new String[] {} );
		testPolicy("cmip5.mymodel", "Write", new String[] { ATT_TYPE1 }, new String[] { ATT_VALUEB } );
		testPolicy("cmip5.mymodel", "Delete", new String[] {}, new String[] {} );
		testPolicy("nasa.jpl.airs.monthly.file", "Read", new String[] { ATT_TYPE3 }, new String[] { ATT_VALUEA } );
		testPolicy("nasa.jpl.airs.monthly.file", "Write", new String[] { ATT_TYPE3 }, new String[] { ATT_VALUEB } );
		testPolicy("", "Read", new String[] {}, new String[] {} );
		testPolicy("cmip5", "", new String[] {}, new String[] {} );
		testPolicy("xxmlsxx", "Read", new String[] { ATT_TYPE4 }, new String[] { ATT_VALUEA } );
		testPolicy("xxmlsxx", "Write", new String[] {}, new String[] {} );
		
	}
	
	@Test
	public void testFreeAccessIgnoreCase() {
		
		testPolicy("/root/free/myfile", "Read", new String[] { ATT_TYPE_ANY }, new String[] { "" } );
		testPolicy("/root/free/myfile", "read", new String[] { ATT_TYPE_ANY }, new String[] { "" } );
		
		testPolicy("/root/free/myfile", "Write", new String[] { ATT_TYPE_NONE }, new String[] { "" } );
		testPolicy("/root/free/myfile", "write", new String[] { ATT_TYPE_NONE }, new String[] { "" } );
		
	}
	
	private void testPolicy(final String resource, final String action, final String[] attribute_types,  final String[] attribute_values) {
		
		final List<PolicyAttribute> attributes = service.getRequiredAttributes(resource, action);
		Assert.assertEquals(attribute_types.length, attributes.size());
		for (int i=0; i<attribute_types.length; i++) {
			final PolicyAttributeImpl pa = new PolicyAttributeImpl(attribute_types[i],attribute_values[i]);
			Assert.assertTrue(attributes.contains(pa));
		}
		
	}

}
