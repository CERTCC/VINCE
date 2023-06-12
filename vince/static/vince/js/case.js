/*#########################################################################
  # VINCE
  #
  # Copyright 2023 Carnegie Mellon University.
  #
  # NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
  # INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
  # UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
  # AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
  # PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
  # MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
  # WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
  #
  # Released under a MIT (SEI)-style license, please see license.txt or contact
  # permission@sei.cmu.edu for full terms.
  #
  # [DISTRIBUTION STATEMENT A] This material has been approved for public
  # release and unlimited distribution.  Please see Copyright notice for non-US
  # Government use and distribution.
  #
  # Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
  # U.S. Patent and Trademark Office by Carnegie Mellon University.
  #
  # This Software includes and/or makes use of Third-Party Software each subject
  # to its own license.
  #
  # DM21-1126
  ########################################################################
*/

function alertmodal(modal,msg) {
    modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p> " +
	       msg + "</p> <div class=\"modal-footer text-right\">" +
	       "<a href=\"#\" class=\"hollow button cancel_confirm\" " +
	       "data-close type=\"cancel\">Ok</a></div></div></div>")
	.foundation('open');
}

function permissionDenied(modal) {
    alertmodal(modal,"Error: You are not permitted to perform this action");
}

function init_modal_markdown() {
    var simplemde = new EasyMDE({element: $("#id_content")[0],
                                 renderingConfig: {
                                     singleLineBreaks: false,
                                 },
                                 status: false,
                                 autoDownloadFontAwesome: false,
                                });
}



function initTooltipster(element, umProfileStore, displayUserCard) {
    /*replaced to use standard jquery tooltip since plugin was failing */
    $(document).tooltip({
        items:'.vviewed',
        tooltipClass: 'tooltipster-default',
        content: function(callback) {
            var userUrl = $(this).attr('href');
            if(umProfileStore.hasOwnProperty(userUrl)){
                callback(umProfileStore[userUrl])
                //displayUserCard(instance, umProfileStore[userUrl]);
                // load from cache
            }
            else {
                $.get(userUrl, function(data) {
                    umProfileStore[userUrl] = data;
                    callback(data);
                });
            }
        }
    });
}


function reloadVendorStats(case_id) {

    $.ajax({
	url: "/vince/casevendor/"+case_id+"/",
        success: function(data) {
    	    $("#vendorlist").html(data);
	    $(document).foundation();
	}});
}



function reloadVendors(case_id, tablet) {
    tablet.replaceData();
    /*$.ajax({
      url: "/vince/ajax_calls/case/vendors/"+case_id+"/",
      success: function(data) {

      }});*/

    reloadVendorStats(case_id);
}

function reloadVuls(case_id, table) {
    $.ajax({
        url: "/vince/ajax_calls/case/vulnerabilities/"+case_id+"/",
        success: function(data) {
            tablet.replaceData(data)
        }});
}

function reloadVendorsNotify(case_id) {
    $.ajax({
        url: "/vince/casevendor/"+case_id+"/notify/",
        success: function(data) {
            $(".vendorlist").html(data);
	    /* reload plugins */
            $(document).foundation();
        }});
}

function reloadArtifacts(case_id) {
    $.ajax({
	url: "/vince/case/"+case_id+"/artifacts/",
	success: function(data) {
	    $(".artifactlist").html(data);
	    /* reload plugins */
            $(document).foundation();
	}});
}

function reloadParticipants(case_id, tablet) {
    $.ajax({
	url: "/vince/ajax_calls/case/participants/"+case_id+"/",
        success: function(data) {
	    tablet.replaceData(data);
        }});
}

function reload_case_activity() {
    var url = $("#case_activity").attr("href");
    $.ajax({
        url: url,
        success: function(data) {
            $("#timeline").html(data);
	    /* reload plugins */
            $(document).foundation();
        }
    });
}

var txhr = null;

function searchComms(e) {
    if (e) {
        e.preventDefault();
    }
    lockunlock(true,'div.mainbody,div.vtmainbody','#timeline');
    window.txhr = $.ajax({
        url: $("#filterform").attr("action"),
        type: "POST",
        data: $('#filterform').serialize(),
        success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
            $("#timeline").html(data);
	    /* reload plugins */
            $(document).foundation();
        },
	error: function() {
            lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
            console.log(arguments);
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
            lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
	    window.txhr = null;
        }
    });
}

function searchTasks(e, tablet) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
	e.preventDefault();
    }

    if (window.txhr && 'abort' in window.txhr) {
        window.txhr.abort();
    }

    var url = $("#filter_tasks").attr("href");
    var sort = $("#filterstatus option:selected").val();
    lockunlock(true,'div.mainbody,div.vtmainbody','#case_tasks');
    window.txhr = $.ajax({
	url : url,
	type: "POST",
	data: {"keyword": $("#filter_tasks").val(),
	       "csrfmiddlewaretoken": csrftoken,
	       "sort": sort
	      },
	success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#case_tasks');
	    tablet.replaceData(data);
	    //$("#case_tasks").html(data);
	},
        error: function() {
            console.log(arguments);
	    lockunlock(false,'div.mainbody,div.vtmainbody','#case_tasks');
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
	    lockunlock(false,'div.mainbody,div.vtmainbody','#case_tasks');
	    window.txhr = null;
        }
    });
}

function getDate( element ) {
    var date;
    try {
        date = $.datepicker.parseDate( dateFormat, element.value );
    } catch( error ) {
        date = null;
    }
    return date;
}

function auto(data, taggle, tag_url, modal) {
    var container = taggle.getContainer();
    var input = taggle.getInput();
    $(input).autocomplete({
	source: data,
	appendTo:container,
	position: { at: "left bottom", of: container },
	select: function(event, data) {
	    event.preventDefault();
	    if (event.which === 1) {
		taggle.add(data.item.value);
		var csrftoken = getCookie('csrftoken');
                $.post(tag_url,
                       {'state': 1, 'add_tag': 1, 'csrfmiddlewaretoken': csrftoken, 'tag':data.item.value }, function(d) {
			   reload_case_activity();
                       })
                    .fail(function(d) {
                        alert("An error occurred while trying to add this tag.");
                        taggle.remove(data.item.value);
                    });

	    }
	}
    });
}

$(document).ready(function() {

    var tabsoughtviaurl = $(location).prop('hash').substr(1);

    $('a').each(function () {
        $(this).qtip({
            content: $(this).attr("title"),
	    style: {classes: 'qtip-youtube'}
	})
    });

    var input = document.getElementById("id_keyword");
    if (input) {
	input.addEventListener("keydown", function(event) {
	    if (event.keyCode == 13) {
		searchComms(event);
	    }
	});
    }

    var form = document.getElementById('filterform');
    if (form) {
	if (form.attachEvent) {
            form.attachEvent("submit", searchComms);
	} else {
            form.addEventListener("submit", searchComms);
	}
    }

    if (document.getElementById("user_taggs")) {
	var tag_url = $("#user_taggs").attr("href");
	var case_id = $('.addvulmodal').attr('caseid');
	var assigned_users = JSON.parse(document.getElementById('assigned_users').textContent);
        var assignable = JSON.parse(document.getElementById('assignable').textContent);
	var tags = [];
	var taggle2 =  new Taggle('user_taggs', {
	    tags: assigned_users,
            duplicateTagClass: 'bounce',
	    preserveCase: true,
            allowedTags: assignable,
	    placeholder: ["Tag a user..."],
	    onTagAdd: function(event, tag) {
		if (event) {
		    var csrftoken = getCookie('csrftoken');
		    var tag_url = $("#user_taggs").attr("href");
		    $.post(tag_url,
			   {'state': 1, 'csrfmiddlewaretoken': csrftoken, 'tag':tag }, function(data) {
			       reload_case_activity();
			       /*reload participants, because this will add a participant */
			       reloadParticipants(case_id, participants_table);
			   })
			.fail(function(data) {
			    permissionDenied(addmodal);
			    taggle2.remove(tag);
			});
		}
	    },
	    onBeforeTagRemove: function(event, tag) {
		if (event) {
		    var tag_url = $("#user_taggs").attr("href");
		    var csrftoken = getCookie('csrftoken');
		    var jqxhr = $.post(tag_url,
				       {'state': 0, 'csrfmiddlewaretoken': csrftoken, 'tag':tag}, function(data) {
					   reload_case_activity();
					   /*reload participants, because this will rm a participant */
					   reloadParticipants(case_id, participants_table);
				       })
			.fail(function(data) {
			    permissionDenied(addmodal);
			    taggle2.add(tag);
			});
		}
		return true;
	    },
	});

	auto(assignable, taggle2, tag_url, addmodal);

    }


    if (document.getElementById("case_taggs")) {

        var case_tags = JSON.parse(document.getElementById('case_tags').textContent);
        var case_avail_tags = JSON.parse(document.getElementById('case_available_tags').textContent);
        var tags = [];
	var case_tag_url = $("#case_taggs").attr("href");
        var casetaggle =  new Taggle('case_taggs', {
            tags: case_tags,
	    tagFormatter: function(li) {
                var node = li.querySelector('.taggle_text');
                var text = node.textContent;
		var link = '<a href="/vince/search/?q='+text+'&facet=Cases"/>';
                $(node).wrapInner(link);
                return li;
            },
            duplicateTagClass: 'bounce',
            allowedTags: case_avail_tags,
            placeholder: ["Tag this case..."],
	    onTagAdd: function(event, tag) {
                if (event) {
		    var case_tag_url = $("#case_taggs").attr("href");
                    var csrftoken = getCookie('csrftoken');
                    $.post(case_tag_url,
                           {'add_tag': 1, 'csrfmiddlewaretoken': csrftoken, 'tag':tag }, function(data) {
                               reload_case_activity();
                           })
                        .fail(function(data) {
			    if (data['responseJSON']['error']) {
				addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['responseJSON']['error']+ "</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\"> Ok</a></div></div></div>").foundation('open');
				casetaggle.remove(tag);
			    } else {
				permissionDenied(addmodal);
				casetaggle.remove(tag);
			    }
                        });
                }
            },
	    onBeforeTagRemove: function(event, tag) {
		if (event) {
		    var case_tag_url = $("#case_taggs").attr("href");
                    var csrftoken = getCookie('csrftoken');
                    var jqxhr = $.post(case_tag_url,
                                       {'del_tag': 1, 'csrfmiddlewaretoken': csrftoken, 'tag':tag}, function(data) {
					   reload_case_activity();
                                       })
			.fail(function(data) {
                            permissionDenied(addmodal);
                            casetaggle.add(tag);
			});
		}
                return true;
            },
        });
        auto(case_avail_tags, casetaggle, case_tag_url, addmodal);

    }



    $("input[id^='id_status_']").change(function(event) {
        searchTickets();
    });

    $(".vendorchoice input").change(function(event) {
        searchComms();
    });

    $("#id_timesort").change(function(event) {
        searchComms();
    });


    $("#id_communication_type").change(function(event) {
        searchComms();
    });

    $("#id_participants").change(function(event) {
	searchComms();
    });


    var dateFormat = "yy-mm-dd",
	from = $( "#id_datestart" )
        .datepicker({
            defaultDate: "+1w",
            changeMonth: true,
            changeYear: true,
            dateFormat: dateFormat,
            numberOfMonths: 1,
            maxDate: "+0D"
        })
        .on( "change", function() {
            /*to.datepicker( "option", "minDate", getDate( this ) );*/
            searchComms();
        }),
        to = $( "#id_dateend" ).datepicker({
            defaultDate: "+1w",
            changeMonth: true,
            changeYear: true,
            dateFormat: dateFormat,
            numberOfMonths: 1,
            maxDate: "+0D"

        })
        .on( "change", function() {
            from.datepicker( "option", "maxDate", getDate( this ) );
            searchComms();
        });

    var addmodal = $("#smallmodal");
    var largemodal = $("#largemodal");

    $(document).on("submit", '#addvendorform', function(event) {
	event.preventDefault();
	var reload = $(this).attr("reload");
	var vendors = [];
	var csrftoken = getCookie('csrftoken');
	var rows = $("#project-description > tr");
	var case_id = $('.addvulmodal').attr('caseid');

	$.each(rows, function(index, item) {
	    vendors.push(item.cells[0].innerText);
	});
	var url = $(this).attr("action");

	$.post(url, {'csrfmiddlewaretoken': csrftoken, 'vendors': vendors,
		     'case_id': case_id}, function(data) {
			 if (reload == "list") {
			     reloadVendors(case_id, vendors_table);
			 } else {
			     reloadVendorsNotify(case_id);
			 }
			 /*remove rows in table */
			 $("#project-description").find("tr").remove();

		     })
	    .fail(function(xhr, status, error) {
		var data = xhr.responseText;
		try {
		    var jsonResponse = JSON.parse(data);
		    console.log(jsonResponse);
		    addmodal.foundation('close');
		    addmodal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+jsonResponse['message']+"</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');
		} catch (e) {
		    permissionDenied(addmodal);
		}
	    })
            .done(function() {
		addmodal.foundation('close');
            });
    });


    $(document).on("click", '#cancelvendor', function(event) {
	$("#project-description").find("tr").remove();
    });

    $(document).on("click", '#changestatus', function(event) {
        event.preventDefault();
	$.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }

	});
    });

    $(document).on("click", '#addnewvendor', function(event) {
        event.preventDefault();
	$.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
		$.getJSON("/vince/api/vendors/", function(data) {
                    vend_auto(data);
		});
            },
            error: function(xhr, status) {
                permissionDenied(addmodal);
            }

        });
    });

    function confirmpushhandler(event){
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
                permissionDenied(addmodal);
            }
        });        
    };

    $(document).on("click", '.confirmpush', confirmpushhandler);

    function postremovehandler(event){
        event.preventDefault();
    	$.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
	        addmodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
		permissionDenied(addmodal);
            }
        });
    };

    $(document).on("click", '.postremove', postremovehandler);

    $(document).on("click", '.addvulmodal', function(event) {
        event.preventDefault();
        var caseid = $(this).attr("caseid");
        $.ajax({
            url: "/vince/case/"+caseid+"/addvul/",
            type: "GET",
            success: function(data) {
	        largemodal.html(data).foundation('open');
		initiate_vul_add_form();
	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }
    	});
    });

    function openposthandler(event){
        event.preventDefault();
        var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
        	addmodal.html(data).foundation('open');
            }
        });
    };

    $(document).on("click", '.openpost', openposthandler);

    $(document).on("click", '.openeditmodal', function(event) {
        event.preventDefault();
        var vulid = $(this).attr("vulid")
        $.ajax({
            url: "/vince/case/editvul/"+vulid+"/",
            type: "GET",
            success: function(data) {
                largemodal.html(data).foundation('open');
		initiate_vul_add_form();
            },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }
        });
    });


    $(document).on("click", '#transfer', function(event) {
	event.preventDefault();
	$.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
		permissionDenied(addmodal);
            }
        });
    });

    $(document).on("click", '.rmparticipant', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }
	});
    });
    async function notify_all() {
	let i = 1;
	let hm = get_modal();
	hm.append("<h2>Start all-vendor Notifications</h2>")
	hm.append("<h4>Do not hit Escape or click outside this window!</h4>");
	hm.append("<p> See Javascript console log for any failures</p>");
	let caseid = $('.addvulmodal').attr('caseid');
	if(!caseid) {
	    hm.append("<strong style='color:red'>Error no CaseID found");
	    return false;
	}

	window.allvendors = [];
	var max = 2;
	hm.append("<h5> Fetching vendors list by Page " +
		  "[<span class='cpage'>0</span>] of " +
		  "<span class='tpage'>2</span> </h5>");
	while (i <= max) {
	    url = 'https://vince.cert.org/vince/ajax_calls/case/vendors/'+
		caseid+'/?page='+String(i);
	    hm.find('.cpage').html(String(i));
            await $.get(url,function(d) {
		if(d.last_page)
		    max = parseInt(d.last_page);
		hm.find('.tpage').html(max);
		if(d.data)
		    window.allvendors = window.allvendors.concat(d.data);
            });
	    i++;
	}
	hm.append("<h4> Initiating contact for vendor # " +
		  "[<span class='mdcounter'>0</span>]  of " +
		  window.allvendors.length + " Vendors in " +
		  "this Case, please wait </h4>");
	hm.append("<div><ul><li><h5>Starting Contact</h5></li>");
	for( let i = 0; i < window.allvendors.length; i++) {
	    hm.find("li:last-child").fadeOut('10000');
	    let si = String(i+1);
	    hm.find('.mdcounter').html(si);
	    let v = window.allvendors[i];
	    let csrf = getCookie('csrftoken');
	    let vuid = "VU#Private";
	    if($('#vuid').val())
		vuid = $('#vuid').val();
	    let fsubmit = { subject : vuid+": New Vulnerability Report",
			    email_template: "",
			    email_body: "We have new information about a " +
			    "vulnerability that may affect your products. " +
			    "Please login to the CERT/CC VINCE portal for " +
			    "more information about this vulnerability." }
	    fsubmit['csrfmiddlewaretoken'] = csrf;
	    if(v.contact_date) {
		console.log("Already Contacted vendor : " + v.vendor);
		hm.append("<li> " + si + " Already Contacted vendor : " +
			  v.vendor + " on " + v.contact_date + "</li>");
		continue;
	    } else {
		console.log("Contacting vendor :  " + v.vendor);
		hm.append("<li> " + si + " Attempting to contact : " + v.vendor +
			  " result is <span class='vendor'" + si +
			  "'></span></li>");
		var url = 'https://vince.cert.org/vince/editcasevendors/' +
		    caseid+'/';
		fsubmit['vendors'] = v.contact_id;
		await $.post(url,fsubmit).done(function(r) {
		    console.log("Contact result is ");
		    console.log(r);
		    console.log(si);
		    hm.find(".vendor " + si).html(JSON.stringify(r));
		    //hm.append(JSON.stringify(r));
		});
	    }
	}
	hm.append("</ul></div>");
	finish_modal(hm);
    }


    async function approve_all_vendors() {
	let hm = get_modal();
	hm.append("<h2>Start all-vendor Approval</h2>");
	hm.append("<h4> Do not close this window </h4>");
	hm.append("<p> See Javascript console log for any failures</p>");
	let caseid = $('.addvulmodal').attr('caseid');
	if(!caseid) {
            hm.append("<strong style='color:red'>Error no CaseID found");
	    finish_modal(hm);
            return false;
	}
	window.allvendors = [];
	var max = 2;
	let url = "https://vince.cert.org/vince/ajax_calls/case/vendors/"+
	    caseid + "/?page=1&filters%5B0%5D%5Bfield%5D=reqapproval" +
	    "&filters%5B0%5D%5Btype%5D=%3D&filters%5B0%5D%5Bvalue%5D=true";
	hm.append("<div><ul><li><h5>Starting Contact</h5></li>");
	await $.getJSON(url,async function(d) {
	    if(d.data) {
		hm.append("<h4> Initiating contact for vendor # " +
			  "[<span class='mdcounter'>0</span>]  of " +
			  d.data.length + " Vendors in " +
			  "this Case, please wait </h4>");
		hm.append("<div><ul><li><h5>Starting Contact</h5></li>");
		for(let i=0; i<d.data.length; i++) {

		    let si = String(i+1);
		    hm.find("li:last-child").fadeOut('10000');
		    hm.find('.mdcounter').html(si);
		    let v = d.data[i];
		    if(v.approved) {
			hm.append("<li> " + si + " Already Approved vendor : " +
				  v.vendor +"</li>");
			continue;
		    }
		    let vurl =  'https://vince.cert.org/vince/vendor/approve/'+
			v.id + '/';
		    hm.append("<li> " + si + " Attempting to contact : " +
			      v.vendor + " result is <span class='vendor" +
			      si + "'></span></li>");
		    await $.post(vurl,
				 { csrfmiddlewaretoken: getCookie('csrftoken'),
				   vendor: v.id
				 },
				 function(y) {

				     hm.find(".vendor" + si).html(JSON.stringify(y));
				 });
		}
	    }

	});
	finish_modal(hm);
    }

    $(document).on("click", '#approveall', approve_all_vendors);
    $(document).on("click", '#notifyall', notify_all);

    //Don't submit the form twice
    $(document).on('submit', '#editvulform', function (e) {
        var $form = $(this);
        if ($form.data('submitted') === true) {
            // Previously submitted - don't submit again
            e.preventDefault();
        } else {
            // Mark it so that the next submit can be ignored
            $form.data('submitted', true);
        }

        return this;

    });



    $(document).on("click", '.makepublic', function(event) {
	event.preventDefault();
	var csrftoken = getCookie('csrftoken');
	var artifact = $(this).attr("artid");
	var url = $(this).attr("href");

	$.post(url, {'csrfmiddlewaretoken': csrftoken, 'artifact': artifact
                    }, function(data) {
			reloadArtifacts(data['case']);
		    })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });
    });


    $(document).on("click", '.downloadcve', function(event) {
	event.preventDefault();
	var vulid = $(this).attr('vulid');
	window.location = "/vince/cve/"+vulid+"/download/";
    });


    $.widget("custom.tablecomplete", $.ui.autocomplete, {
	_create: function() {
	    this._super();
	    this.widget().menu("option", "items", "> tr:not(.ui-autocomplete-header)");
	},
	_renderMenu(ul, items) {
	    var self = this;
	    //table definitions
	    var $t = $("<table class=\"unstriped hover\">", {
		border: 1
	    }).appendTo(ul);
	    $t.append($("<thead>"));
	    $t.find("thead").append($("<tr>", {
		class: "ui-autocomplete-header"
	    }));
	    var $row = $t.find("tr");
	    $("<th>").html("Name").appendTo($row);
	    $("<tbody>").appendTo($t);
	    $.each(items, function(index, item) {
		self._renderItemData(ul, $t.find("tbody"), item);
	    });
	},
	_renderItemData(ul, table, item) {
	    return this._renderItem(table, item).data("ui-autocomplete-item", item);
	},
	_renderItem(table, item) {
	    var $row = $("<tr>", {
		class: "ui-menu-item",
		role: "presentation"
	    })
	    $("<td>").html(item.value).appendTo($row);
	    return $row.appendTo(table);
	}
    });

    function renderTable(p, item) {
        var self = this;
        //table definitions
	var $row = $("<tr>", {
            class: "ui-menu-item",
            role: "presentation"
        })
        $("<td>").html(item.value).appendTo($row);
	$row.appendTo(p)
    }



    function _doFocusStuff(event, ui) {
	if (ui.item) {
	    var $item = ui.item;
	    $("#vendor").val($item.value);
	    /*$("#project-description").html($item.value);*/
	}
	return false;
    }

    function _doSelectStuff(event, ui) {
	if (ui.item) {
	    var $item = ui.item;
	    renderTable("#project-description", $item);
	    $("#vendor").val('');
	    $("#vendor").focus();
	}
	return false;
    }

    function vend_auto(data) {
	var autocomplete = $("#vendor").tablecomplete({
	    minLength: 1,
	    source: data,
	    focus: _doFocusStuff,
	    select: _doSelectStuff

	});
	// create the autocomplete

	// get a handle on it's UI view
	var autocomplete_handle = autocomplete.data("ui-autocomplete");
    }


    /*
      $(window).keydown(function(event){
      if(event.keyCode == 13) {
      event.preventDefault();
      return false;
      }
      });
    */
    var vendorinput = document.getElementById("vendor");
    if (vendorinput) {
	vendorinput.addEventListener("keydown", function(event) {
            if (event.keyCode == 13) {
                event.preventDefault();
                renderTable("#project-description", {value:$("#vendor").val(), label:$("#vendor").val()});
                $("#vendor").val('');
                $("#vendor").focus();
            }
        });
    }

    $(document).on("click", '.changetype', function(event) {
	event.preventDefault();
	var assign_block = $("#change_type_block").html();
        $(this).parent().hide();
        $(this).parent().parent().append(assign_block);
    });

    $(".assigned").on("click", "a", function(event) {
	event.preventDefault();
	var assign_block = $("#task_assign").html();
	$(this).parent().hide();
	$(this).parent().parent().append(assign_block);
    });

    $(document).on("click", "#type_submit", function(event) {
        event.preventDefault();
        var val = $(".coord_assign:last").val()
	if (val == "coordinator") {
	    val = "True";
	} else {
	    val = "False";
	}
        var csrftoken = getCookie('csrftoken');
        var url = $(this).parent().prev().attr('href');

        $.post(url, {'csrfmiddlewaretoken': csrftoken, 'coordinator': val},
               function(data) {
		   reloadParticipants($(".addvulmodal").attr('caseid'), participants_table);
               })
            .done(function() {
                /*$("#assign_block").hide();
                  $(".assigned_to").show();*/
		console.log("done");
            })
	    .fail(function(d) {
                permissionDenied(addmodal);
	    });
    });

    $(document).on("click", "#type_cancel", function(event) {
        $("#change_type_block").hide();
        $("#coordtype").show();
    });

    var approvemodal = $("#approvenote");

    function publishvulnotehandler(event) {
        event.preventDefault();
        var url = $(this).attr("action");
	
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                approvemodal.html(data).foundation('open');
            },
            error: function(xhr, status) {
                permissionDenied(addmodal);
            }
        });            
    }

    $(document).on("click", ".publishvulnote", publishvulnotehandler)

    $(document).on("click", ".rmdep", function(event) {
        event.preventDefault();
	var url = $(this).attr("href");

        $.ajax({
	    url: url,
	    type: "GET",
            success: function(data) {
                approvemodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }

        });

    });

    $(document).on("click", ".adddep", function(event) {
        event.preventDefault();
        var url = $(this).attr("action");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		approvemodal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }

	});
    });

    $(document).on("click", ".case-edit", function(event) {
        var url = $(this).attr("href");
        event.preventDefault();
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                approvemodal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }

	});

    });
    /*
    //in vulmodal.js
    var cwe_formset = $('.cwe_formset').length;
    if (cwe_formset) {
    $('.cwe_formset').formset({
    prefix: 'cwe',
    deleteText: '',
    addText: '<i class=\'fas fa-plus\'></i> add cwe',
    addCssClass: 'button tiny primary',
    deleteCssClass: 'remove-formset right'
    });
    }


    var ref_formset = $('.ref_formset').length;
    if (ref_formset) {
    $('.ref_formset').formset({
    prefix: 'ref',
    deleteText: '',
    addText: '<i class=\'fas fa-plus\'></i> add reference',
    addCssClass: 'button tiny primary',
    deleteCssClass: 'remove-formset right'
    });
    }

    var exploit_formset = $('.exploit_formset').length;
    if (exploit_formset) {
    $('.exploit_formset').formset({
    prefix: 'exploit',
    deleteText: '',
    addText: '<i class=\'fas fa-plus\'></i> add exploit',
    addCssClass: 'button tiny primary',
    deleteCssClass: 'remove-formset right'
    });
    }*/

    $('#moreVendor').click(function(e) {
        $("#hidevendors").toggle();
        $("#moreVendors").toggle();
        $("#lessVendors").toggle();
        e.preventDefault();
    });

    $('#lessVendor').click(function(e) {
        $("#hidevendors").toggle();
        $("#moreVendors").toggle();
        $("#lessVendors").toggle();
        e.preventDefault();

    });


    if (document.getElementById('vuls_data')) {
        var data = JSON.parse(document.getElementById('vuls_data').textContent);
	console.log(data);
    }


    var cellClickFunction = function(e, cell) {
        var url_mask = "/vince/vuls/edit/" + cell.getRow().getData().id;
        window.location = url_mask;
    };

    function printFormatter(cell, formatterParams, onRendered){
	return cell.getValue() ? "YES" : "NO";
    }

    var buttonFormatter = function(cell,  formatterParams, onRendered) {
        var rv = "<a vulid="+cell.getValue()+" href=\"#\" title=\"edit this vulnerability\" class=\"openeditmodal btn-link\"><i class=\"fas fa-pencil-alt\"></i></a><button title=\"clone this vulnerability\" class=\"clonevul btn-link\" obj="+cell.getValue()+"><i class=\"far fa-clone\"></i></button><button title=\"delete this vulnerability\" class=\"deletevul btn-link\" href=\""+cell.getRow().getData().remove_link+"\"><i class=\"fas fa-trash-alt\"></i></button>";
	/*if (cell.getRow().getData().ask_vendor_status) {
	  rv = rv + "<a vulid="+cell.getValue()+" href=\"#\" title=\"do not ask for status\" class=\"nosharevul btn-link\"><i class=\"fas fa-unlink\"></i></button>";
	  } else {
	  rv = rv + "<a vulid="+cell.getValue()+" href=\"#\" title=\"ask for status\" class=\"sharevul btn-link\"><i class=\"fas fa-link\"></i></button>";
	  }*/
	return rv
    }



    function cveFormatter(cell, formatterParams, onRendered){
	if (cell.getRow().getData().cveallocation) {
	    return "<a href=\"/vince/cve/"+ cell.getRow().getData().cveallocation + "/edit/\">CVE-" + cell.getValue() +"</a>   <a href=\"#\" class=\"downloadcve\" vulid=\""+ cell.getRow().getData().cveallocation + "\" title=\"download json file\"><i class=\"fas fa-file-download\"></i></a>"
	} else {
	    return cell.getValue() ? "CVE-"+cell.getValue() : "" ;
	}
    }


    $(document).on("click", '.deletevul', function(event) {
	$.ajax({
	    url: $(this).attr("href"),
            success: function(data) {
		approvemodal.html(data).foundation('open');
	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }
	});
    });

    $(document).on("click", '.clonevul', function(event) {
        $.ajax({
            url: "/vince/case/clonevul/" + $(this).attr("obj") + "/",
            success: function(data) {
		largemodal.html(data).foundation('open');
		initiate_vul_add_form();

	    },
	    error: function(xhr, status) {
                permissionDenied(addmodal);
            }
	});
    });



    $(document).on("click", '.nosharevul', function(event) {
	event.preventDefault();
        var vulid = $(this).attr("vulid")
        $.ajax({
            url: "/vince/case/editvul/"+vulid+"/?noask=1",
            type: "GET",
            success: function(data) {
		reloadVuls($(".addvulmodal").attr('caseid'), table)
            },
            error: function(xhr, status) {
                permissionDenied(addmodal);
            }
        });
    });

    $(document).on("click", '.sharevul', function(event) {
        event.preventDefault();
        var vulid = $(this).attr("vulid")
        $.ajax({
            url: "/vince/case/editvul/"+vulid+"/?ask=1",
            type: "GET",
            success: function(data) {
		reloadVuls($(".addvulmodal").attr('caseid'), table)
            },
            error: function(xhr, status) {
                permissionDenied(addmodal);
            }
        });
    });


    var vulCellClick = function(e, cell) {
	var url_mask = "/vince/vul/" + cell.getRow().getData().id;
	window.location = url_mask;
    };

    //define custom formatter function
    var tagFormatter = function(cell, formatterParams, onRendered){
        var values = cell.getValue();
        var tags = "";

        if(values){
            values.forEach(function(value){
                tags += "<span class='tag'>" + value + "</span>";
            });
        }
        return tags;
    }

    if (data) {
	var tablet = new Tabulator("#vuls-table", {
            data:data,
            layout:"fitColumns",
	    placeholder: "No vulnerabilites have been added",
	    tooltipsHeader:true,
            columns:[
		{title:"ID", field:"cert_id", cellClick: vulCellClick},
                {title:"Description", field:"description", cellClick: vulCellClick},
                {title:"CVE", field:"cve", formatter:cveFormatter, cellClick: vulCellClick},
                {title:"CWE", field:"cwe", cellClick: vulCellClick},
		{title:"Exploits", field:"exploits", cellClick: vulCellClick},
                {title:"Date Added", field:"date_added", cellClick: vulCellClick},
		{title:"Tags", field:"tags", formatter:tagFormatter, width:250, cellClick:vulCellClick},
                {formatter:buttonFormatter, align:"center", field:"id"}
            ],

        });
    }

    function contactClickFunction(cell, formatterParams, onRendered) {
	var val = cell.getValue();
	if (cell.getRow().getData().users == 0) {
	    val = "<i class=\"fas fa-exclamation-circle warning\"></i>  " + val
	}
	if (cell.getRow().getData().alert_tags.length) {
	    val = "<i class=\"fas fa-bell warning\"></i>  " + val
	}

        var url_mask = cell.getRow().getData().contact_link;
	return "<a href=\""+url_mask+"\">"+ val + "</a>";
    }

    function vendorToolTipFunction(cell) {
	if (cell.getRow().getData().alert_tags.length) {
	    return "This Vendor is tagged with an ALERT Tag: " + cell.getRow().getData().alert_tags[0]
	}

	if (cell.getRow().getData().users == 0) {
	    return "This vendor does not have any VINCE Users";
	} else {
	    return "This vendor has VINCE Users";
	}
    }
    function eyeFormatter(cell, formatterParams, onRendered) {
	var url_mask = "/vince/casevendor/" + cell.getRow().getData().id + "/viewed/";
	return cell.getValue() ? "<a href=\"" + url_mask + "\" class=\"vviewed\"><i class=\"fas fa-eye primary\"></i></a>" : "<a href=\"" + url_mask + "\" class=\"vviewed\"><i class=\"fas fa-eye-slash warning\"></i></a>";
    }

    function appFormatter(cell, formatterParams, onRendered) {
	if (cell.getValue()) {
	    if (cell.getRow().getData().approved) {
		return "<i class=\"fas fa-check primary\"></i>";
	    } else {
		return "<i class=\"fas fa-user-edit warning\"></i>";
	    }
	} else if (cell.getRow().getData().statement_date) {
	    return "<i class=\"fas fa-user-edit warning\"></i>";
	}
    }

    function vendorNotificationFormatter(cell, formatterParams, onRendered) {
	if (cell.getValue()) {
	    return "<a href=\""+cell.getValue()+"\"><i class=\"fas fa-inbox\"></i>";
	}
    }

    function stmtFormatter(cell, formatterParams, onRendered) {
	if (cell.getValue()) {
	    return "<a href=\"" + cell.getValue() + "\" class=\"openmodal button cmu tiny\" data-open=\"statusmodal\"> View Statement</a>";
	}
	return "";
    }

    function statusClickFunction(cell) {
	var url_mask = "/vince/casevendor/" + cell.getRow().getData().id + "/status/";
	return {url: url_mask};
    }


    var dateEditor = function(cell, onRendered, success, cancel, editorParams) {
	var editor = document.createElement("input");

	editor.setAttribute("type", "date");

	editor.value = cell.getValue();

	//set focus on the select box when the editor is selected (timeout allows for editor to be added to DOM)
	onRendered(function(){
            editor.focus();
            editor.style.css = "100%";
	});

	function successFunc(){
            success(editor.value, "YYYY-MM-DD");
	}

	editor.addEventListener("change", successFunc);
	editor.addEventListener("blur", successFunc);

	return editor;
    };


    function vendornotifiedFormatterFunction(cell, formatterParams, onRendered) {

	return "Notified <i class=\"far fa-edit\"></i>";
    }


    $(document).on("click", ".notnotified", function(event) {
	event.preventDefault();
	vendors_table.setFilter("contact_date", "=", "false");
    });

    $(document).on("click", ".allvendors", function(event) {
        event.preventDefault();
        vendors_table.clearFilter();
    });

    function customFilter(data, filterParams) {
	if (data) {
            if (data.approved) {
                return false;
            } else {
		if (data.statement_date) {
                    return true;
		}
            }
	}
	return false;
    }

    function customFilter2(data, filterParams) {
	console.log(data);
	if (data) {
	    if (data.approved) {
		return true;
	    }
	}
	return false;
    }

    function customNouserfilter(data, filterParams) {
	return (data.users == 0);
    }

    $(document).on("click", ".reqapproval", function(event) {
        event.preventDefault();
        vendors_table.setFilter("reqapproval", "=", "true");
    });

    $(document).on("click", ".vendorsnousers", function(event) {
        event.preventDefault();

        vendors_table.setFilter("users", "=", "0");
    });

    $(document).on("click", ".vendorapproved", function(event) {
	event.preventDefault();
	vendors_table.setFilter("approved", "=", "true");
    });

    function custom3(data, filterParams) {
        return (data.seen == true);
    }

    $(document).on("click", ".vendorsseen", function(event) {
	event.preventDefault();
	vendors_table.setFilter("seen", "=", "true");
    });

    $(document).on("click", ".vendorsresponded", function(event) {
        event.preventDefault();
        vendors_table.setFilter("statement_date", "!=", "false");
    });

    var vendors_table = new Tabulator("#vendors-table", {
        //data:vendors_data, //set initial table data
	data:[],
        layout:"fitColumns",
	selectable:true,
	ajaxURL: "/vince/ajax_calls/case/vendors/"+$(".addvulmodal").attr('caseid')+"/",
	ajaxProgressiveLoad:"scroll",
	ajaxFiltering:true,
	ajaxLoaderLoading: "<div style='display:inline-block; border:4px solid #333; border-radius:10px; background:#fff; font-weight:bold; font-size:16px; color:#000; padding:10px 20px;'>Loading Data</div>",
	tooltipsHeader:true,
	placeholder: "No vendors.",
	selectableCheck:function(row){
            //row - row component
            return row.getData().tagged == false; //allow selection of untagged rows
	},
        columns:[
            {title:"Vendor", field:"vendor", formatter:contactClickFunction, tooltip:vendorToolTipFunction, width:200, headerFilter:"input"},
            {title:"Status", field:"status", formatter: "link", formatterParams:statusClickFunction, headerFilter:"input"},
	    {titleFormatter:vendornotifiedFormatterFunction, field:"contact_date", editor:dateEditor, cellEdited: function(cell) {
                var csrftoken = getCookie('csrftoken');
                $.post(cell.getRow().getData().edit_date_url,
                       {'csrfmiddlewaretoken': csrftoken, 'new_date':cell.getRow().getData().contact_date},
	               function(data) {
			   approvemodal.html(data).foundation('open');
		       });
	    }},
            {title:"Seen", field:"seen", formatter: eyeFormatter, width:100},
            {title:"Approved", field:"user_approved", formatter: appFormatter},
            {title:"Statement", field:"statement", formatter:stmtFormatter},
	    {title:"Emails", field:"vendor_notification", formatter: vendorNotificationFormatter},
        ],

    });

    reloadVendorStats($(".addvulmodal").attr('caseid'));
    //select row on "select all" button click
    $("#select-all-vendors").click(function(){
	/*vendors_table.selectRow("visible");*/
	vendors_table.selectRow('active');
	var selectedRows = vendors_table.getSelectedRows();
        for (i=0; i < selectedRows.length; i++) {
	    if (selectedRows[i].getData().tagged) {
		vendors_table.deselectRow(selectedRows[i]);
	    }
	}
    });

    //deselect row on "deselect all" button click
    $("#deselect-all-vendors").click(function(){
	vendors_table.deselectRow();
    });

    var flag = false;

    approvemodal.bind("closed", function() {
	flag = true;
    });


    function sleep(ms) {
	return new Promise(resolve => setTimeout(resolve, ms));
    }


    $(document).on("click", '#remove-vendor', function(event) {
	event.preventDefault();
	var selectedRows = vendors_table.getSelectedRows();
	flag = true;
	var ajaxCalls = selectedRows.length;
	var counter = 0;
	var ajaxCallComplete = function() {
	    counter++;
	    if( counter >= ajaxCalls ) {
		// When all ajax calls has been done
		// Do something like hide waiting images, or any else function call
		console.log("Done removing vendors");
		reloadVendors($(".addvulmodal").attr('caseid'), vendors_table);
	    }
	};

	for (i=0; i < selectedRows.length; i++) {
            while (flag == false) {
                window.setTimeout(checkFlag, 100);
	    }
	    if (selectedRows[i].getData().rm_confirm) {
		flag = false;
		$.ajax({
		    url: selectedRows[i].getData().remove_link,
		    success: function(data) {
			approvemodal.html(data).foundation('open');
			counter++;
                    },
		    error: function(xhr, status) {
                        permissionDenied(approvemodal);
                    }});
	    } else {
		$.ajax({

                    url: selectedRows[i].getData().remove_link,
                    success: function(data) {
			ajaxCallComplete();
		    },
		    error: function(xhr, status) {
                        permissionDenied(approvemodal);
                    }});
		flag = true;
	    }
	}
    });
    function alertmodal(modal,msg) {
	modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p> " +
		   msg + "</p> <div class=\"modal-footer text-right\">" +
		   "<a href=\"#\" class=\"hollow button cancel_confirm\" " +
		   "data-close type=\"cancel\">Ok</a></div></div></div>")
            .foundation('open');
    }
    vendors_table = Tabulator.prototype.findTable("#vendors-table")[0]
    approvemodal = $("#approvenote");
    function notify_vendors(event,bypass) {
	event.preventDefault();
	var vendors = [];
        var selectedRows = vendors_table.getSelectedRows();
	var url = $("#vendor_notify").attr("action");
	var csrftoken = getCookie('csrftoken');
	var exceptions = "";
	if (selectedRows.length > 0) {
	    for (i=0; i < selectedRows.length; i++) {
		var v = selectedRows[i].getData();
		if(v.contact_date && (!bypass)) {
		    exceptions += "<h5>Skipping Vendor <u>"+ v.vendor +
			"</u> Already notified on <i>"+ v.contact_date +
			"</i></h5>";
		    continue;
		}
		vendors.push(v.id)
	    }
	    if (vendors.length < 1) {
		alertmodal(approvemodal, "<h4><strong>No valid vendors to " +
			   "notify!</strong></h4><h5>All vendors have been " +
			   "notified or none were selected that can be "+
			   "notified.</h5>");
		approvemodal.find(".modal-footer")
		    .prepend("&nbsp;")
		    .prepend($("<button>").addClass("button cmu")
			     .html("Notify anyway!")
			     .on("click",function(e) {
				 notify_vendors(e,true);
			     }));
		return;
	    }
	} else {
	    alertmodal(approvemodal, "<h4><strong>Select a vendor to be " +
		       "notified!");
	    return;
	}
	if(exceptions != "") {
	    exceptions = '<div style="background: rgb(244, 68, 68); ' +
		'color: white;">' + exceptions + '</div>';
	}
	var formdata = {'vendors': vendors, 'csrfmiddlewaretoken': csrftoken};

	$.post(url, formdata,
               function(data) {
		   approvemodal.html(data+exceptions).foundation('open');
               })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });

    }
    $(document).off("click", '#notifyvendors');
    $(document).on("click", '#notifyvendors', function(event) {
	notify_vendors(event,false);
    });

    $(document).on("click", "#submit_vendors", function(event) {
	event.preventDefault();
	$("#submit_vendors").attr("disabled", true);
        approvemodal.foundation('close');
	var selectedRows = vendors_table.getSelectedRows();
	var formdata = $("#vendornotifyform").serializeArray();
	var vendors = [];
        if (selectedRows.length > 0) {
	    for (i=0; i < selectedRows.length; i++) {
		vendors.push(selectedRows[i].getData().contact_id)
	    }

	    formdata.push({'name':"vendors", 'value': vendors});
            formdata.push({'name':"subject", 'value': $("#id_subject").val()});
            formdata.push({'name':"email_body", "value": $("#id_email_body").val()});
            var url = $("#vendornotifyform").attr("action");
            $.post(url, formdata,
		   function(data) {
                       location.reload();
		   })
		.fail(function(d) {
                    permissionDenied(addmodal);
		});
	}

    });

    $(document).on("submit", "#case-edit-form", function(event) {
	event.preventDefault();
	$.post($(this).attr("action"), $(this).serializeArray(),
	       function(data) {
		   reload_case_activity();
	       })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });
	approvemodal.foundation('close');
    });


    $(document).on("submit", "#changedateform", function(event) {
	event.preventDefault();
	$.post($(this).attr("action"), $(this).serializeArray(),
               function(data) {
               })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });
        approvemodal.foundation('close');
    });

    $(document).on("click", ".cancel_confirm", function(event) {
	event.preventDefault();
	approvemodal.foundation('close');
	reloadVendors($(".addvulmodal").attr('caseid'), vendors_table);
    });

    $(document).on("submit", "#removevendorform", function(event) {
	event.preventDefault();
	$.post($(this).attr("action"), $(this).serializeArray(),
	       function(data) {})
	    .done(function() {
		reloadVendors($(".addvulmodal").attr('caseid'), vendors_table);
	    })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });
	approvemodal.foundation('close');

    })


    function participantClickFunction(cell, formatterParams, onRendered) {
    	var url_mask = cell.getRow().getData().link;
	if (url_mask) {
	    return "<a href=\""+url_mask+"\">"+cell.getValue()+"</a>";
	} else {
	    return cell.getValue();
	}
    };


    function statusFormatter(cell, formatterParams, onRendered) {
	if (cell.getValue()) {
	    return cell.getValue();
	} else {
            return "Staged";
	}
    }

    function participantSeenFormatter(cell, formatterParams, onRendered) {
	if (cell.getValue()) {
	    return "<i class=\"fas fa-eye primary\" title=\"Participant viewed the case\"></i>"
	} else {
	    return "<i class=\"fas fa-eye-slash warning\" title=\"Participant has not viewed the case\"></i>"
	}
    }

    function roleFormatterFunction(cell, formatterParams, onRendered) {
        return "Role <i class=\"far fa-edit\"></i>";
    }

    var participants_table = null;

    function ticketClickFunction(cell) {
	var url_mask = cell.getRow().getData().url;
	return {url: url_mask}
    };

    function statusFormatterFunction(cell, formatterParams, onRendered) {
        return "Status <i class=\"far fa-edit\"></i>";
    }

    function assigneeFormatterFunction(cell, formatterParams, onRendered) {
        return "Assignee <i class=\"far fa-edit\"></i>";
    }

    function ticket_status_update(status) {
	if (status == "2") {
	    return "Reopened";
	} else if (status == "3") {
	    return "Resolved";
	} else if (status == "4") {
	    return "Closed";
	} else {
	    return "In Progress";
	}
    }

    var assignable_users = JSON.parse(document.getElementById('user_data').textContent);
    tasks_table = new Tabulator("#case_tasks", {
        ajaxURL:"/vince/ajax_calls/case/tasks/"+$(".addvulmodal").attr("caseid"),
	ajaxProgressiveLoad:"scroll",
        layout:"fitColumns",
	tooltipsHeader:true,
	placeholder: "You do not have any pending tickets.",
        columns:[
            {title:"ID", field:"ticket", formatter: "link", formatterParams:ticketClickFunction},
            {title:"Title", field:"title", formatter: "link", formatterParams:ticketClickFunction},
            {titleFormatter:assigneeFormatterFunction, field:"assigned_to", editor:"select", editorParams: function(cell) {
		var options = {};
		$.each(assignable_users, function(index, value) {
		    $.each(value, function(k, v) {
			options[k] = v;
		    });
		});
		return options;
	    }, cellEdited: function(cell) {
		var csrftoken=getCookie('csrftoken');
		var url = cell.getRow().getData().url + "?assign=" + cell.getRow().getData().assigned_to;
		$.get(url, function(data) {})
		    .done(function() {
			window.location.reload(true);
		    });

	    }
	    },
	    {titleFormatter:statusFormatterFunction, field:"status", editor:"select", editorParams: {values: {"2":"Reopened", "4":"Closed", "6":"In Progress", "3":"Resolved"}},
	     cellEdited: function(cell) {
		 var csrftoken = getCookie('csrftoken');
		 $.post(cell.getRow().getData().url,
			{'csrfmiddlewaretoken': csrftoken, 'new_status':cell.getRow().getData().status},
			function(data) {})
		     .done(function() {
			 tasks_table.updateData([{id:cell.getRow().getData().id, status:ticket_status_update(cell.getRow().getData().status)}])
		     })
		     .fail(function(d) {
			 permissionDenied(addmodal);
		     });
	     }
	    },
            {title:"Resolution", field:"resolution"},
	    {title:"Modified", field:"date"},
        ],

    });

    $(".task_status").on("click", "a", function(event) {
        event.preventDefault();
        var href = $(this).parent().parent().attr("href");
        var csrftoken = getCookie('csrftoken');
        $.post(href,
               {'csrfmiddlewaretoken': csrftoken, 'new_status':$(this).attr("val")},
               function(data) {})
            .done(function(data, textStatus, jqXHR) {
                console.log("post succeeded (textStatus: " + textStatus + ")");
                window.location.reload(true);
            })
	    .fail(function(d) {
                permissionDenied(addmodal);
            });
    });

    $(document).on("click", ".task_assign_cancel", function(event) {
	$(this).parent().prev().show();
	$(this).parent().remove();

    });

    $(document).on("click", ".task_assign_submit", function(event) {
	/*var txt = $(this).prev();*/
	var val = $(".task_reassign:last").val();
	var href = $(this).parent().parent().parent().attr("href");
	var url = href + "?assign="+val;
	$.get(url, function(data) {})
            .done(function() {
		window.location.hash ='#tasks';
		window.location.reload(true);
            })
	    .fail(function(d) {
                permissionDenied(adddepmodal);
            });

    });



    var filter_task = document.getElementById("filter_tasks");
    if (filter_task) {
	filter_task.addEventListener("keyup", delaySearch(function(event) {
            searchTasks(event, tasks_table);
        },1000));
    }

    $("#filterstatus").change(function(event) {
        searchTasks(event, tasks_table);
    });


    $(document).on("change", "#id_email_template", function() {
	var vuid = $(this).attr("vuid");
        $.ajax({
            url: "/vince/api/template/"+$(this).val()+"/",
            type: "GET",
            success: function(data) {
		$("#id_subject").val(vuid + " " + data['subject']);
                $("#id_email_body").val(data['body']);
            }
        });
    });

    $(document).on("submit", "#publishsubmit", function(event) {
	$("#publishbtn").prop("disabled", true);
	return true;
    });


    $(document).on("click", "#askapproval", function(event) {
	var csrftoken = getCookie('csrftoken');
	$.post($(this).attr("href"), {
            "csrfmiddlewaretoken": csrftoken,
	},
               function(data) {
                   window.location=data['location'];
               });
    });

    var umProfileStore = {};

    var displayUserCard = function(instance, data) {
        instance.content(data);
    }

    initTooltipster(".vviewed", umProfileStore, displayUserCard);

    $(document).on("click", "#mutecase", function(event) {
        event.preventDefault();
        var csrftoken = getCookie('csrftoken');
        var data = {'csrfmiddlewaretoken': csrftoken};
        var post = $.post($(this).attr("href"), data);
        var button = $(this);
	post.done(function(data) {
            button.html(data["button"]);
        });
    });

    $(document).on("closed.zf.reveal", "#statusmodal", function(event) {
	var case_id = $('.addvulmodal').attr('caseid');
	reloadVendors(case_id, vendors_table);
    });


    $(document).on("submit", "#notifyform", function(e) {
	var $form = $(this);

	if ($form.data('submitted') === true) {
	    // Previously submitted - don't submit again
	    e.preventDefault();
	} else {
	    // Mark it so that the next submit can be ignored
	    $form.data('submitted', true);
	}
        // Keep chainability
	return this;
    });

    function initialize_participants_tab() {

        if (document.getElementById('participant_data')) {
            var participants_data = JSON.parse(document.getElementById('participant_data').textContent);
            console.log(data);
        }    

        $(document).on("click", '#cancelparticipant', function(event) {
            $("#user-description").find("tr").remove();
        });

        $(document).on("click", '#notifyparticipants', function(event) {
            event.preventDefault();
            var vendorlist = "";
            var selectedRows = participants_table.getSelectedRows();
            if (selectedRows.length > 0) {
		if (selectedRows.length > 1) {
		    $("#error-participant-msg").html("Please only notify 1 participant at a time.");
		    $("#error-participant").foundation('open');
		} else {
		    var cpid= selectedRows[0].getData().id;
		    
		    $.ajax({
			url: "/vince/notify/"+cpid+"/",
			type: "GET",
			success: function(data) {
			    addmodal.html(data).foundation('open');
			    
			},
			error: function(xhr, status) {
			    permissionDenied(addmodal);
			}
		    });
		}
            } else {
		$("#error-participant-msg").html("Please choose a participant");
		$("#error-participant").foundation('open');
            }
	    
        });

        function _doFocusUserStuff(event, ui) {
            if (ui.item) {
                var $item = ui.item;
                $("#user").val($item.value);
            }
            return false;
        }
	
        function _doSelectUserStuff(event, ui) {
            if (ui.item) {
                var $item = ui.item;
                renderTable("#user-description", $item);
                $("#user").val('');
                $("#user").focus();
            }
            return false;
        }
	
	
        function _doFocusContactStuff(event, ui) {
            if (ui.item) {
                var $item = ui.item;
                $("#contact").val($item.value);
            }
            return false;
        }
	
        function _doSelectContactStuff(event, ui) {
            if (ui.item) {
                var $item = ui.item;
                renderTable("#user-description", $item);
                $("#contact").val('');
                $("#contact").focus();
            }
            return false;
        }
	
        function user_auto(data) {
            var autocomplete = $("#user").tablecomplete({
                minLength: 1,
                source: data,
                focus: _doFocusUserStuff,
                select: _doSelectUserStuff
		
            });
        }
	
	
        function contact_auto(data) {
            var autocomplete = $("#contact").tablecomplete({
		minLength: 1,
		source: data,
		focus: _doFocusContactStuff,
		select:_doSelectContactStuff
            });
        }
	

        var input = document.getElementById("newuser");
        if (input) {
            input.addEventListener("keydown", function(event) {
		if (event.keyCode == 13) {
		    event.preventDefault();
		    renderTable("#user-description", {value:$("#newuser").val(), label:$("#newuser").val()});
		    $("#newuser").val('');
		    $("#newuser").focus();
		}
            });
        }
	
        /*$.getJSON("/vince/api/vendors/", function(data) {
          vend_auto(data);
          });*/
	
        $.getJSON("/vince/api/users/", function(data) {
            user_auto(data);
        });
	
        $.getJSON("/vince/api/contacts/", function(data) {
            contact_auto(data);
        });
	
        $("#adduserform").submit(function(event) {
            event.preventDefault();
            var vendors = [];
            var csrftoken = getCookie('csrftoken');
            var rows = $("#user-description > tr");
            var case_id = $(this).attr('case');
	    
            $.each(rows, function(index, item) {
                vendors.push(item.cells[0].innerText);
            });
            var url = "/vince/addparticipant/";
	    
            $.post(url, {'csrfmiddlewaretoken': csrftoken, 'users': vendors,
                         'case_id': case_id}, function(data) {
			     reloadParticipants(case_id, participants_table);
                         })
                .done(function() {
                    $("#adduser").foundation('close');
		})
		.fail(function(d) {
		    permissionDenied(addmodal);
                });
        });
	
        if (participants_data) {
            participants_table = new Tabulator("#participant-table", {
                data:participants_data, //set initial table data
                layout:"fitColumns",
		tooltipsHeader:true,
                selectable:true,
		dataEdited:function(data) {
		    
		    var csrftoken=getCookie('csrftoken');
		    for (i=0; i < data.length; i++) {
			var url = data[i].changetype;
			var type = data[i].role;
			if (type == "Coordinator") {
			    type = "True";
			} else {
			    type = "False";
			}
			$.post(url, {'csrfmiddlewaretoken': csrftoken, 'coordinator': type},
			       function(data) {
			       })
			    .done(function() {
				reloadParticipants($(".addvulmodal").attr('caseid'), participants_table);
				
			    })
			    .fail(function(d) {
				permissionDenied(addmodal);
			    });
		    }
		},
		placeholder: "There are no participants in this case",
                columns:[
                    {title:"Name", field:"name", formatter:participantClickFunction},
                    {title:"Date Notified", field:"notified"},
                    {titleFormatter: roleFormatterFunction, field:"role", editor:"select", editorParams: {values: {"Coordinator":"Coordinator", "Reporter":"Reporter"}}},
		    {title:"Seen", field:"seen", formatter:participantSeenFormatter},
		    {title:"Status", field:"status", formatter: statusFormatter},
                ],
		
            });
        }
	
        //select row on "select all" button click
        $("#select-all-participants").click(function(){
            participants_table.selectRow();
        });
	
        //deselect row on "deselect all" button click
        $("#deselect-all-participants").click(function(){
            participants_table.deselectRow();
        });
        
        $(document).on("click", '#remove-participant', function(event) {
            event.preventDefault();
            var selectedRows = participants_table.getSelectedRows();
            flag = true;
            for (i=0; i < selectedRows.length; i++) {
                while (flag == false) {
                    window.setTimeout(checkFlag, 100);
                }
                if (selectedRows[i].getData().rm_confirm) {
		    flag = false;
		    $.ajax({
                        url: selectedRows[i].getData().remove_link,
                        success: function(data) {
			    approvemodal.html(data).foundation('open');
                        },
			error: function(xhr, status) {
			    permissionDenied(approvemodal);
			}});
                } else {
		    $.ajax({
                        url: selectedRows[i].getData().remove_link,
                        success: function(data) {
			    sleep(2000);
			    reloadParticipants($(".addvulmodal").attr('caseid'), participants_table);
                        },
			error: function(xhr, status) {
			    permissionDenied(approvemodal);
			}});
		    flag = true;
                }
            }
	    
            reloadParticipants($(".addvulmodal").attr('caseid'), participants_table);
        });

    }

    function initialize_vulnote_tab() {

        function downloadvulnote(){
            let format = $(this).data('format');
            let JSONvulnoteurl = $('#download_json').attr('href');
            /*jsPDF default properties ratio, xmax, ymax  */
            let rt = 6;
            let lineChars = 95;
            let randClass = Math.random().toString(32).substr(2);
            $.getJSON(JSONvulnoteurl).done(function(JSONdata){
                if(!("content" in JSONdata)) {
                    console.log("Error");
                    console.log(JSONdata);
                    return
                }
                let cleanText = JSONdata.content.replace(/\“/g, "\"").replace(/\”/g, "\"").replace(/\’/g, "\'").replace(/\—/g, "\-");
                var tarea = document.createElement("textarea");
                tarea.style.display = "none";
                tarea.id = "ccB";
                document.body.appendChild(tarea);
                var simplemde = new EasyMDE({element: tarea});
                var simpleHTML = simplemde.markdown(cleanText);
                if (format === "html") {
                    var link = document.createElement("a");
                    link.download = $('#vutitle').html() + " - Notice (Draft).html";
                    link.href = "data:text/html;charset=utf8," + encodeURIComponent(simpleHTML);
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    document.body.removeChild(tarea);
                    delete tarea;
                    delete link;
                    return;
                } else if (format === "pdf") {
                    let doc = new jsPDF();
                    let fClass = '.' + randClass;
                    let specialElementHandlers = {};
                    specialElementHandlers = {
                        [fClass]: function (e, o) {
                            if(!('href' in e)) {
				return false;
                            }
                            if(e.innerHTML == e.href) {
				console.log(e);
				return false;
                            }
                            if(e.href.indexOf("http") != 0){
				return false;
                            }
                            let xid = Math.random().toString(32).substr(2);
                            $(e).attr('id',xid);
                            // stick the id at the beginning the innerText of the <a> element. This is to ensure that we're counting to the right instance of (for example) "Google" if
                            // Google is mentioned multiple times in the html element that contains our current <a>:
                            e.innerText = e.id + e.innerText;
			    
                            // acquire the parent of the <a> element:
                            let m = $(e).parent();
                            let mstringbeforexid = m.text().split(xid)[0];
                            let wordsinmbeforexid = mstringbeforexid.replace(/\s+/g,' ').split(" ");
			    
                            // remove the id we put at the beginning of the innerText of the <a> element
                            e.innerText = e.innerText.substring(e.id.length);
			    
                            let wordsine = e.innerText.split(" ");
                            let widthsofar = parseInt(doc.getTextWidth(wordsinmbeforexid[0])/rt)
                            let ycounter = 0;
                            let x = 0;
                            let y = 0;
			    
                            // this bit gets us the x and y position where the text before the <a> tag ends:
                            for (let i = 1; i < wordsinmbeforexid.length; i++){
				if (widthsofar + parseInt(doc.getTextWidth(" " + wordsinmbeforexid[i])/rt) < margins.width) {
                                    widthsofar += parseInt(doc.getTextWidth(" " + wordsinmbeforexid[i])/rt);
				} else {
                                    ycounter++
                                    widthsofar = parseInt(doc.getTextWidth(wordsinmbeforexid[i])/rt)
				}
                            }
                            if (widthsofar != 0){
				widthsofar += parseInt(doc.getTextWidth(" ")/rt);
                            }
			    
                            // there are now two cases. Either the text of the link together with the text preceding it in the <a>'s parent exceeds the margin, or not. If not, then no word wrap affects the positioning
                            // of the link, so we can just place the link at the found location, as follows:
                            if (widthsofar + parseInt(doc.getTextWidth(e.innerText)/rt) < margins.width) {
				x = margins.left + widthsofar;
				y = o.y + ycounter * 4.3;
				doc.link(x,y,parseInt(doc.getTextWidth(e.innerText)/rt),5,{url: e.href})
                            } else {
				
				// But if the text of the link together with the text preceding it in the <a>'s parent does exceed the margin, then we have to loop through the words in the link text, as follows:
				let widthoflinktextsofar = 0;
				for (let i = 0; i < wordsine.length; i++) {
				    
                                    if (widthsofar + widthoflinktextsofar + parseInt(doc.getTextWidth(wordsine[i])/rt) <= margins.width) {
					widthoflinktextsofar += parseInt(doc.getTextWidth(wordsine[i] + " ")/rt)
					if (i === wordsine.length - 1) {
                                            x = margins.left + widthsofar;
                                            y = o.y + ycounter * 4.3;
                                            doc.link(x,y,widthoflinktextsofar,5,{url: e.href})    
					}
                                    } else {
					x = margins.left + widthsofar;
					y = o.y + ycounter * 4.3;
					doc.link(x,y,widthoflinktextsofar,5,{url: e.href})
					widthsofar = 0
					ycounter++
					widthoflinktextsofar = parseInt(doc.getTextWidth(wordsine[i])/rt)
					if (i === wordsine.length - 1) {
                                            x = margins.left
                                            y = o.y + ycounter * 4.3;
                                            doc.link(x,y,widthoflinktextsofar,5,{url: e.href})
					}
                                    }
				}
                            }
                            return false;
			}
                    }
		    let tempdivid = 'd' + randClass;
                    $('#' + tempdivid).remove();
                    simpleHTML = simpleHTML.replace(/<br>\\*/ig,"</p><p>");
                    $('body').append($('<div>')
				     .attr('id',tempdivid).html(simpleHTML)
				     .css('display','none'));
                    $('#' + tempdivid + 'hr').each(function() {
			$(this).after($("<p>").append($("<hr>")));
			$(this).remove();
                    });
                    $('#' + tempdivid + ' a').addClass(randClass);
		    $('#' + tempdivid + ' a').each(function() {
			let el = this;
			if(el.innerHTML == el.href) {
                            let u = new URL(el.innerText);
			    /* Change URL and www in URL's to avoid fromHTML autolinking */
                            let sturl = u.host.replace(/^www\./i,'') + u.pathname;
                            let fakeUrl =  u.protocol[0].toUpperCase() + u.protocol.substr(1) + '//'+ sturl + u.search;
                            if(fakeUrl.length > lineChars) {
				fakeUrl =   u.protocol[0].toUpperCase() + u.protocol.substr(1) + '//'+sturl.substr(0,lineChars - 12 - u.protocol.length) + '...';
                            } 
                            el.innerText = fakeUrl;
			}
                    });
                    simpleHTML = $('#'+tempdivid).html();
                    margins = {
			bottom:10,
			top:15,
			left:10,
			right:10,
			width:170
                    };
                    doc.setPage(0);
                    doc.setFont("helvetica");
                    doc.setFontType("normal");
                    doc.setTextColor(220,220,220);
                    doc.setFontSize(70);
                    doc.text("EMBARGOED", 50, doc.internal.pageSize.height - 120, null, 45); 
                    doc.fromHTML(
			simpleHTML,
			margins.left,
			margins.top,
			{
                            'width': margins.width,
                            'elementHandlers': specialElementHandlers
			},
			function (dispose) {
			},
			margins
                    );
                    var pageCount = doc.internal.getNumberOfPages();
                    for(i = 0; i < pageCount; i++) { 
			doc.setPage(i);
			// Set header
			let amberPosition = 94.5;
			let amberTop = 3
			doc.setFillColor(0,0,0);
			doc.rect(amberPosition, amberTop, 21.2, 5, 'F');
			
			doc.setFont("times");
			doc.setFontType("bold");
			doc.setFontSize(10);
			doc.setTextColor(245, 194, 66);
			doc.text(amberPosition,amberTop+4, "TLP:AMBER");
			
			doc.setFontSize(10);
			doc.setTextColor(255,0,0);
			doc.text(19, 12, "The information within this document is to " +
				 "be restricted to participants’ organizations only " +
				 "until publicly released.");
			
			doc.setFontSize(10);
			doc.setTextColor(150);
			doc.text(7, 5, "EMBARGOED");
			doc.text(179, 5, "EMBARGOED");
			
			// Set footer
			let amberBottom = 275
			doc.setFillColor(0,0,0);
			doc.rect(amberPosition, amberBottom, 21.2, 5, 'F');
			
			doc.setFont("times");
			doc.setFontType("bold");
			doc.setFontSize(10);
			doc.setTextColor(245, 194, 66);
			doc.text(amberPosition,amberBottom+4, "TLP:AMBER");
                    }
                    doc.save($('#vutitle').html() + " - Notice (Draft).pdf");
                    $('#' + tempdivid).remove();
		}
            }).fail(function() {
                console.log("The getJSON request didn't work for some reason.");
            });
        }

        $('.downloadvulnote').on('click',downloadvulnote);
	
        $(document).on("click", "#approvevulnote", function(event) {
            event.preventDefault();
            var url = $(this).attr("action");
	    
            $.ajax({
                url: url,
                type: "GET",
                success: function(data) {
                    approvemodal.html(data).foundation('open');
                },
                error: function(xhr, status) {
                    permissionDenied(addmodal);
                }
            });
        });
        
        $(document).on("click", "#publishvulnote", publishvulnotehandler);
        
        $(document).on("click", "#sharevulnote", function(event) {
            event.preventDefault();
            var url = $(this).attr("action");
	    
            $.ajax({
                url: url,
                type: "GET",
                success: function(data) {
                    approvemodal.html(data).foundation('open');
                    init_modal_markdown();
                },
                error: function(xhr, status) {
                    permissionDenied(addmodal);
                }
		
            });
        });
    };

    function initialize_posts_tab() {
        $(document).on("click", '#confirmpush', confirmpushhandler);
        $(document).on("click", '#postremove', postremovehandler);
        $(document).on("click", '#openpost', openposthandler);
    };

    if (tabsoughtviaurl) {
        if (tabsoughtviaurl === "participants") {
            initialize_participants_tab();
        } else if (tabsoughtviaurl === "vulnote") {
            initialize_vulnote_tab();
        } else if (tabsoughtviaurl === "posts") {
            initialize_posts_tab();
        };
    };

    function initialize_tab_js(mutation) {
        if (mutation[0]) {
            if (mutation[0].target.getAttribute('id') === "participants"){
                initialize_participants_tab();
            } else if (mutation[0].target.getAttribute('id') === "vulnote") {
                initialize_vulnote_tab();
            } else if (mutation[0].target.getAttribute('id') === "posts") {
                initialize_posts_tab();
            };
        };
    };
    
    let tab_observer = new MutationObserver(initialize_tab_js);

    let participants_tab = document.getElementById("participants");
    let vulnote_tab = document.getElementById("vulnote");
    let posts_tab = document.getElementById("posts");

    tab_observer.observe(participants_tab, {childList:true});
    tab_observer.observe(vulnote_tab, {childList:true});
    tab_observer.observe(posts_tab, {childList:true})


});
