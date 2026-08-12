$(function() {
    /* $(document).foundation(); */
    $('[data-tabs]').on('change.zf.tabs', function(_, _, t) {
	if(t && t.attr('id') == 'csaf')
	    to_csaf();
	else
	    from_csaf();
    });
    let editor = ace.edit('mjsoneditor');
    editor.setTheme("ace/theme/xcode");
    editor.session.setMode("ace/mode/json");
    editor.session.setUseWrapMode(true);
    editor.setValue("{}");
    function simpleCopy(original) {
	return JSON.parse(JSON.stringify(original));
    }
    function to_csaf() {
	try {
	    let csaf = generate_csaf_vulform();
	    if(csaf)
		editor.setValue(JSON.stringify(csaf,null,2),-1);
	} catch(e) {
	    editor.setValue("{}");
	    console.log(e);
	}
    }
    function from_csaf() {
	let csaf = JSON.parse(editor.getValue());
	if(typeof(csaf) == "object" && csaf.document)
	    populate_vulform_from_csaf(csaf);
    }
    function generate_csaf_vulform() {
	const now = new Date();

	const yyyymmddhhmmss = now.getFullYear() +
	      String(now.getMonth() + 1).padStart(2, '0') +
	      String(now.getDate()).padStart(2, '0') +
	      String(now.getHours()).padStart(2, '0') +
	      String(now.getMinutes()).padStart(2, '0') +
	      String(now.getSeconds()).padStart(2, '0');
	let ndate = now.toISOString();
	let csaf = {
	    "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
	    "document": {
		"acknowledgments": [],
		"category": "Vulnerability Reporting Form",
		"csaf_version": "2.1",
		"distribution": {
		    "tlp": {
			"label": "AMBER",
			"url": "https://www.first.org/tlp/"
		    }
		},
		"publisher": {
		    "category": "discoverer",
		},
		"tracking": {
		    "current_release_date": ndate,
		    "generator": {
			"date": ndate,
			"engine": {
			    "name": "VINCE",
			    "version": "3.0.44"
			}
		    },
		    "id": "VRF-####",
		    "initial_release_date": ndate,
 		    "revision_history": [
 			{
 			    "date": ndate,
 			    "number": "1." + yyyymmddhhmmss + ".1",
 			    "summary": "Submitted on " + ndate
 			}
 		    ],
		    "status": "final",
		    "version": "1." + yyyymmddhhmmss + ".1"
		}
	    },
	    "product_tree": {"branches": [{}] },
	    "vulnerabilities": [
		{
		    "metrics": [
			{
			    "content": {
				"ssvc_v2": {
				    "schemaVersion": "2.0.0",
				    "selections": [
					{
					    "key": "E",
					    "name": "Exploitation",
					    "namespace": "ssvc",
					    "values": [
						{
						    "key": "A",
						    "name": "Active"
						}
					    ],
					    "version": "1.1.0"
					}
				    ],
				    "timestamp": ndate
				}
			    },
			    "products": [
				"CSAFPID-0001"
			    ]
			}
		    ],
		    "involvements": [
			{
			    "date": ndate,
			    "party": "discoverer",
			    "status": "contact_attempted",
			    "summary": ""
			},
			{
			    "party": "discoverer",
			    "summary": "",
			    "status": "open"
			}
		    ],
		    "notes": [
			{
			    "category": "description",
			    "text": "",
			    "title": "Vulnerability Description"
			},
			{
			    "audience": "coordinator",
			    "category": "other",
			    "text": "",
			    "title": "Vulnerability Discovery Method"
			}
		    ],
		    "product_status": {
			"known_affected": [
			    "CSAFPID-0001"
			]
		    }, 
		    "references": [],
		    "threats": [],
		    "title": ""
		}
	    ],
	    "x_extensions": [
		{
		    "$schema": "https://cert.org/cvd/csaf_2.1_root_extension_1.0.1.json",
		    "category": "high_value",
		    "critical": false,
		    "content": {
		    }
		}
	    ]
	}
	function truncateString(str, maxLength) {
	    if(!maxLength)
		maxLength = 100;
	    if (str.length <= maxLength) return str;
	    let truncated = str.slice(0, maxLength);
	    const lastSpaceIndex = truncated.lastIndexOf(' ');
	    const lastDotIndex = truncated.lastIndexOf('.');
	    const lastValidIndex = Math.max(lastSpaceIndex, lastDotIndex);
	    if (lastValidIndex > 0) {
		truncated = truncated.substring(0, lastValidIndex);
	    }
	    return truncated.replace(/[. ]+$/, '') + '...';
	}

	const vulform = Object.fromEntries(
	    $('#vulform').serializeArray().map(item => [item.name, item.value])
	);
	const why_no_attempt = {1: "I have not attempted to contact any vendors",
				2: "I have been unable to find contact information for a vendor",
				3: vulform.please_explain}
	if(String(vulform["comm_attempt"]) == "False") {
	    csaf.vulnerabilities[0].involvements[0] = {"status": "not_contacted",
						       "summary": why_no_attempt[vulform.why_no_attempt],
						       "party": "discoverer"
						      };
	}else {
	    csaf.vulnerabilities[0].involvements[0] = {"status": "contact_attempted",
						       "summary": vulform.vendor_communication || "Vendor was communicated",
						       "date": new Date(vulform.first_contact).toISOString(),
						       "party": "discoverer"
						      };
	}
	let product_array = ["CSAFPID-0001"];
	csaf.product_tree = {"branches": [{}]};
	csaf.product_tree.branches[0].name = vulform.vendor_name;
	csaf.product_tree.branches[0].category = "vendor";
	csaf.product_tree.branches[0].branches = [{}];
	csaf.product_tree.branches[0].branches[0].category = "product_name";
	csaf.product_tree.branches[0].branches[0].name = vulform.product_name;
	csaf.product_tree.branches[0].branches[0].branches = [{}];
	csaf.product_tree.branches[0].branches[0].branches[0].category = "product_version";
	csaf.product_tree.branches[0].branches[0].branches[0].name = vulform.product_version;
	let product_id = {"name": vulform.vendor_name + " " + vulform.product_name
			  + " " + vulform.product_version,
			  "product_id": "CSAFPID-0001"
			 }
	csaf.product_tree.branches[0].branches[0].branches[0].product = product_id;
	if(vulform.multiplevendors == "True") {
	    let othervendors = vulform.other_vendors.split(/\r?\n|,/).filter(Boolean);
	    /*Assume exactly same product name and product version is impacted
	     for all the vendors */
	    othervendors.forEach(function(vendor, i) {
		csaf.product_tree.branches.push({});
		let tbranch = csaf.product_tree.branches.at(-1);
		let pid = "CSAFPID-000" + String(i + 2);
		tbranch.name = vendor;
		tbranch.category = "vendor";
		tbranch.branches = simpleCopy(csaf.product_tree.branches[0].branches);
		tbranch.branches[0].branches[0].product.product_id = pid;
		product_array.push(pid);
	    });
	}
	csaf.vulnerabilities[0].product_status = {"known_affected": product_array};
	if(vulform.ics_impact == "on") {
	    csaf.x_extensions[0].content.ics_impact = true;
	} else {
	    csaf.x_extensions[0].content.ics_impact = false;
	}
	if(vulform.ai_ml_system == "on") {
	    csaf.x_extensions[0].content.ai_ml_system = true;
	} else {
	    csaf.x_extensions[0].content.ai_ml_system = false;
	}
	let vul_title = truncateString(vulform.vul_description, 100);
	csaf.document.title = "Vulnerability Reporting Form";
	csaf.vulnerabilities[0].notes = [{},{}];
	csaf.vulnerabilities[0].title = vul_title;
	csaf.vulnerabilities[0].notes[0].text = vulform.vul_description;
	csaf.vulnerabilities[0].notes[0].category = "description";
	csaf.vulnerabilities[0].notes[0].title = "Vulnerability Description";
	csaf.vulnerabilities[0].notes[1].text = vulform.vul_discovery;
	csaf.vulnerabilities[0].notes[1].audience = "coordinator";
        csaf.vulnerabilities[0].notes[1].category =  "other";
        csaf.vulnerabilities[0].notes[1].title = "Vulnerability Discovery Method";
	csaf.vulnerabilities[0].threats = [{},{}];
	csaf.vulnerabilities[0].threats[0].category =  "exploit_status";
	csaf.vulnerabilities[0].threats[0].details = vulform.vul_exploit ;
	csaf.vulnerabilities[0].threats[1].category =  "impact";
	csaf.vulnerabilities[0].threats[1].details = vulform.vul_impact;
	delete csaf.vulnerabilities[0].references;
	if(vulform.vul_public == "True") {
	    csaf.vulnerabilities[0].references = [];
	    let urls = vulform.public_references.split(/\r?\n/).filter(Boolean);
	    if(urls.length) {
		urls.forEach(function(url) {
		    try {
			new URL(url)
		    } catch(e) {
			alert("Invalid URL Ignored " + url);
			return;
		    }	
		    csaf.vulnerabilities[0].references.push({"category": "external",
							     "summary": "Publicly Known References",
							     "url": url});
		});
	    }
	}
	if(vulform.vul_exploited == "True") {
	    if(!csaf.vulnerabilities[0].references)
		csaf.vulnerabilities[0].references = [];
	    let urls = vulform.exploit_references.split(/\r?\n/).filter(Boolean);
	    if(urls.length) {
		urls.forEach(function(url) {
		    try {
			new URL(url)
		    } catch(e) {
			alert("Invalid URL Ignored " + url);
			return;
		    }
		    csaf.vulnerabilities[0].references.push({"category": "external",
							     "summary": "Publicly Exploited References",
							     "url": url})
		});
	    }
	    csaf.vulnerabilities[0].metrics[0].products = product_array;
	} else {
	    delete csaf.vulnerabilities[0].metrics;
	}
	if(vulform.vul_disclose == "True") {
	    csaf.vulnerabilities[0].involvements[1] = {"party": "discoverer",
						       "summary": vulform.disclosure_plans || "Will disclose soon",
						       "status": "open"
						      };
	}
	csaf.document.publisher.name = vulform.contact_name;

	csaf.document.publisher.issuing_authority = vulform.contact_org;

	csaf.document.publisher.namespace = "mailto:" + vulform.contact_email;

	if(vulform.share_release == "True") {
	    csaf.x_extensions[0].content.share_contact_with_vendor = true;
	} else {
	    csaf.x_extensions[0].content.share_contact_with_vendor = false;
	}
	if(vulform.credit_release == "True") {
	    csaf.document.acknowledgments = [{names:[]}];
	    csaf.document.acknowledgments[0].names[0] = vulform.contact_name;
	    csaf.document.acknowledgments[0].organization = vulform.contact_org;
	}else {
	    delete csaf.document.acknowledgments;
	}
	if(vulform.tracking) {
	    csaf.x_extensions[0].content.Tracking_IDs = vulform.tracking;
	} else {
	    delete csaf.x_extensions[0].content.Tracking_IDs;
	}
	
	if(vulform.comments) {
	    csaf.x_extensions[0].content.private_comments = vulform.comments;
	} else {
	    delete csaf.x_extensions[0].content.private_comments;
	}
	if(vulform.reporter_pgp) {
	    try {
		new URL(vulform.reporter_pgp) 
		csaf.x_extensions[0].content.contact_pgp_url = vulform.reporter_pgp;
	    } catch(e) {
		csaf.x_extensions[0].content.contact_pgp_ascii = vulform.reporter_pgp;
	    }
	}
	return csaf;
    }

    function populate_vulform_from_csaf(csafInput) {
	const csaf = (typeof csafInput === "string") ? JSON.parse(csafInput) : csafInput;
	const $form = $("#vulform");

	function setField(name, value, options = {}) {
	    const $els = $form.find('[name="' + name+ '"]');
	    if (!$els.length) return;

	    const normalized = (value === undefined || value === null) ? "" : String(value);
	    const trigger = options.trigger !== false;

	    if ($els.first().attr("type") === "radio") {
		$els.prop("checked", false);
		const $target = $els.filter('[value="' + normalized + '"]');
		if ($target.length) {
		    $target.prop("checked", true);
		    if (trigger) $target.trigger("change");
		}
		return;
	    }

	    if ($els.first().attr("type") === "checkbox") {
		if ($els.length === 1) {
		    const checked = normalized === "on" || normalized === "true" || normalized === "True" || normalized === "1";
		    $els.prop("checked", checked);
		    if (trigger) $els.trigger("change");
		} else {
		    $els.each(function () {
			const shouldCheck = Array.isArray(value) && value.map(String).includes($(this).val());
			$(this).prop("checked", shouldCheck);
			if (trigger) $(this).trigger("change");
		    });
		}
		return;
	    }

	    $els.val(normalized);
	    if (trigger) $els.trigger("change");
	}

	function get(obj, path, fallback = undefined) {
	    try {
		return path.split(".").reduce((acc, k) => (acc == null ? undefined : acc[k]), obj) ?? fallback;
	    } catch {
		return fallback;
	    }
	}

	function toDateInputValue(iso) {
	    if (!iso) return "";
	    const d = new Date(iso);
	    if (Number.isNaN(d.getTime())) return "";
	    return d.toISOString().slice(0, 10);
	}

	function validUrl(u) {
	    try {
		new URL(u);
		return true;
	    } catch {
		return false;
	    }
	}

	const vuln = get(csaf, "vulnerabilities.0", {});
	let productBranches = get(csaf, "product_tree.branches", []);
	const vendorBranch = get(productBranches, "0", {});
	const productBranch = get(vendorBranch, "branches.0", {});
	const xext = (csaf.x_extensions || [])[0] || {};
	const xcontent = xext.content || {};

	setField("contact_name", get(csaf, "document.publisher.name", ""));
	setField("contact_org", get(csaf, "document.publisher.issuing_authority", ""));
	const namespace = get(csaf, "document.publisher.namespace", "");
	setField("contact_email", namespace.startsWith("mailto:") ? namespace.slice(7) : "");
	setField("vendor_name", get(vendorBranch, "name", ""));
	setField("product_name", get(productBranch, "name", ""));
	setField("product_version", get(productBranch, "name", ""));

	const descriptionNote = (vuln.notes || []).find(n => n.category === "description") || {};
	const discoveryNote = (vuln.notes || []).find(n => n.title === "Vulnerability Discovery Method") || (vuln.notes || [])[1] || {};
	setField("vul_description", descriptionNote.text || get(vuln, "title", ""));
	setField("vul_discovery", discoveryNote.text || "");
	setField("vul_exploit", get(vuln, "threats.0.details", ""));
	setField("vul_impact", get(vuln, "threats.1.details", ""));
	const involvement0 = get(vuln, "involvements.0", {});
	const commAttempt = involvement0.status === "contact_attempted";
	setField("comm_attempt", commAttempt ? "True" : "False");

	if (commAttempt) {
	    setField("vendor_communication", involvement0.summary || "");
	    setField("first_contact", toDateInputValue(involvement0.date));
	} else {
	    const summary = involvement0.summary || "";
	    if (summary === "I have not attempted to contact any vendors") {
		setField("why_no_attempt", "1");
		setField("please_explain", "");
	    } else if (summary === "I have been unable to find contact information for a vendor") {
		setField("why_no_attempt", "2");
		setField("please_explain", "");
	    } else {
		setField("why_no_attempt", "3");
		setField("please_explain", summary);
	    }
	}

	const involvement1 = get(vuln, "involvements.1", {});
	const hasDisclosure = involvement1 && involvement1.status === "open" && (involvement1.summary || "").trim() !== "";
	setField("vul_disclose", hasDisclosure ? "True" : "False");
	if (hasDisclosure) setField("disclosure_plans", involvement1.summary || "");

	const refs = vuln.references || [];
	const publicRefs = refs
	      .filter(r => (r.summary || "").toLowerCase().includes("publicly known"))
	      .map(r => r.url)
	      .filter(Boolean);

	const exploitRefs = refs
	      .filter(r => (r.summary || "").toLowerCase().includes("exploited"))
	      .map(r => r.url)
	      .filter(Boolean);

	const vulPublic = publicRefs.length > 0;
	const vulExploited = !!get(vuln, "metrics.0.content.ssvc_v2"); 
	setField("vul_public", vulPublic ? "True" : "False");
	setField("public_references", publicRefs.join("\n"));

	setField("vul_exploited", vulExploited ? "True" : "False");
	setField("exploit_references", exploitRefs.join("\n"));

	setField("ics_impact", xcontent.ics_impact ? "on" : "");
	const aiVal = (xcontent.ai_ml_system === true);
	setField("ai_ml_system", aiVal ? "on" : "");

	setField("share_release", xcontent.share_contact_with_vendor ? "True" : "False");
	const multi = (!!xcontent.multiple_vendors_impacted)  ||
	      (productBranches.length > 1);
	setField("multiplevendors", multi ? "True" : "False");
	const others = Array.isArray(xcontent.multiple_vendors) ? xcontent.multiple_vendors : [];
	if((others.length == 0) && (multi === true ) ) {
	    /* Skip first branch and get name with category vendor of
	       all branch first elements */
	    let other_vendors = productBranches.slice(1).map(function(u) {
		if(u.category == "vendor")
		    return u.name;
	    }).filter(Boolean).join('\n');
	    setField("other_vendors", other_vendors);
	} else {
	    setField("other_vendors", others.join("\n"));
	}

	const hasAck = Array.isArray(csaf.document?.acknowledgments) && csaf.document.acknowledgments.length > 0;
	setField("credit_release", hasAck ? "True" : "False");

	setField("tracking", xcontent.Tracking_IDs || "");
	setField("comments", xcontent.private_comments || "");

	if (xcontent.contact_pgp_url && validUrl(xcontent.contact_pgp_url)) {
	    setField("reporter_pgp", xcontent.contact_pgp_url);
	} else if (xcontent.contact_pgp_ascii) {
	    setField("reporter_pgp", xcontent.contact_pgp_ascii);
	} else {
	    setField("reporter_pgp", "");
	}

	$form.trigger("change");
    }
    function load_example(url) {
	$.getJSON(url || "certcc-vu_834248.json").done(function(csaf) {
	    populate_vulform_from_csaf(csaf);
	});
    }
});

function getCookie(name) {
    const m = document.cookie.match(new RegExp("(^|;\\s*)" + name + "=([^;]+)"));
    return m ? decodeURIComponent(m[2]) : null;
}

async function submitCsafMultipart(csaf, fileInputEl) {
    const csrftoken = getCookie("csrftoken");
    const fd = new FormData();
    const now = new Date();
    const yyyymmddhhmmss = now.getFullYear() +
	  String(now.getMonth() + 1).padStart(2, '0') +
	  String(now.getDate()).padStart(2, '0') +
	  String(now.getHours()).padStart(2, '0') +
	  String(now.getMinutes()).padStart(2, '0') +
	  String(now.getSeconds()).padStart(2, '0');
    let ndate = now.toISOString();
    if(!csaf)
	csaf = {
	     "$schema": "https://docs.oasis-open.org/csaf/csaf/v2.1/schema/csaf.json",
	    "document":{
		"category": "CERT/CC Vulnerability Request Form",
                "distribution": {
                    "tlp": {
                        "label": "AMBER",
                        "url": "https://www.first.org/tlp/"
                    }
                },
                "title": "Vul Report",
                "csaf_version": "2.1",
		"publisher": {
		    "category": "discoverer",
		    "name": "Alice",
		    "issuing_authority": "Org",
		    "namespace": "mailto:alice@example.com"
		},
		"acknowledgments": [
		    {
			"names": ["Alice"]
		    }
		],
		"tracking": {
		    "current_release_date": ndate,
		    "generator": {
			"date": ndate,
			"engine": {
			    "name": "VINCE",
			    "version": "3.0.44"
			}
		    },
		    "id": "VRF-####",
		    "initial_release_date": ndate,
 		    "revision_history": [
 			{
 			    "date": ndate,
 			    "number": "1." + yyyymmddhhmmss + ".1",
 			    "summary": "Submitted on " + ndate
 			}
 		    ],
		    "status": "final",
		    "version": "1." + yyyymmddhhmmss + ".1"
		}
	    },
	    "product_tree": {
		   "branches": [
		       {
			   "category": "vendor",
			   "name": "Vendor",
			   "branches": [
			       {
				   "category": "product_name",
				   "name": "Product",
				   "branches": [
				       {
					   "category": "product_version",
					   "name": "1.0.0",
					   "product": {
					       "name": "Vendor Product 1.0.0",
					       "product_id": "CSAFPID-0001"
					   }
				       }
				   ]
			       }
			   ]
		       }
		   ]
	    },
	    "vulnerabilities": [
		{
		    "title": "Fallback title",
		    "notes": [
			{
			    "category": "description",
			    "text": "Description from note"
			},
			{
			    "audience": "coordinator",
			    "category": "other",
			    "title": "Vulnerability Discovery Method",
			    "text": "Discovery text"
			}
		    ],
		    "threats": [
			{
			    "category": "impact",
			    "details": "Impact details"
			},
			{
			    "category": "exploit_status",
			    "details": "Exploit details"
			}
		    ],
		    "involvements": [
			{
			    "status": "contact_attempted",
			    "party": "discoverer",
			    "summary": "Reached out to vendor",
			    "date": ndate
			},
			{
			    "status": "open",
			    "party": "discoverer",
			    "summary": "Public disclosure timeline"
			}
		    ],
		    "references": [
			{
			    "summary": "Publicly known reference",
			    "url": "https://example.com/public"
			},
			{
			    "summary": "Actively exploited in the wild",
			    "url": "https://example.com/exploit"
			}
		    ],
		    "metrics": [
			{
			    "content": {
				"ssvc_v2": {
				    "schemaVersion": "2.0.0",
				    "selections": [
					{
					    "key": "E",
					    "name": "Exploitation",
					    "namespace": "ssvc",
					    "values": [
						{
						    "key": "A",
						    "name": "Active"
						}
					    ],
					    "version": "1.1.0"
					}
				    ],
				    "timestamp": ndate
				}
			    },
			    "products": [
				"CSAFPID-0001"
			    ]
			}
		    ]
		}
	    ],
	    "x_extensions": [
		{
		    "$schema": "https://cert.org/cvd/csaf_2.1_root_extension_1.0.1.json",
		    "category": "high_value",
		    "critical": false,
		    "content": {
			"ics_impact": false,
			"ai_ml_system": false,
			"share_contact_with_vendor": true,
			"private_comments": "Private note"
		    }
		}
	    ]
	}
    fd.append("csaf", JSON.stringify(csaf));
    const file = fileInputEl?.files?.[0];
    if (file) fd.append("user_file", file);
    fd.append("csrfmiddlewaretoken", csrftoken || "");
    const res = await fetch("/vince/comm/api/vulreport/", {
	method: "POST",
	credentials: "include",
	headers: {
	    "X-CSRFToken": csrftoken,
	    "Accept": "application/json"
	},
	body: fd
    });
    const data = await res.json().catch(() => ({}));
    console.log("status:", res.status, "response:", data);
    return { ok: res.ok, status: res.status, data };
}
