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


function permissionDenied(modal) {

    modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: You are not permitted to perform this action</p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\">Ok</a></div></div></div>").foundation('open');

}

function inputValue(q,v){
    var e=document.querySelector(q);
    if(!e||e.nodeName.toLowerCase()!='input')
	return;
    if(arguments.length>1){
	e.value=v;
	return e
    }
    return e.value
}


function updateScores() {
    var result=CVSS31.calculateCVSSFromMetrics(
	inputValue('input[type="radio"][name=AV]:checked'),
	inputValue('input[type="radio"][name=AC]:checked'),
	inputValue('input[type="radio"][name=PR]:checked'),
	inputValue('input[type="radio"][name=UI]:checked'),
	inputValue('input[type="radio"][name=S]:checked'),
	inputValue('input[type="radio"][name=C]:checked'),
	inputValue('input[type="radio"][name=I]:checked'),
	inputValue('input[type="radio"][name=A]:checked'),
	inputValue('input[type="radio"][name=E]:checked'),
	inputValue('input[type="radio"][name=RL]:checked'),
	inputValue('input[type="radio"][name=RC]:checked'));

    console.log(result);
    if(result.success===!0) {
	$("#cvss_vector").html(result.vectorString);
	$("#cvss_severity").html(result.baseSeverity);
	$("#cvss_base").html(result.baseMetricScore);
	$("#cvsinfo").show();
	return true;
	
    } else {

	$("#errorfield").html("<div class=\"callout alert\">All Base Metrics are required to calculate score.</div>");
	$("#errorfield").show();
	$('input').focus();
	return false;
    }


}

function add_tag(taggle, tag, modal){
    var csrftoken = getCookie('csrftoken');
    var url = $("#vul_taggs").attr("action");
    $.post(url,
           {'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'add_tag': true}, function(data) {
               console.log("success adding");
           })
        .fail(function (data) {
            console.log(data);
            if (data['responseJSON']['error']) {
		if (modal) {
                    modal.html("<div class\"fullmodal\"><div class=\"modal-body\"><p>Error: "+data['responseJSON']['error']+"/p> <div class=\"modal-footer text-right\"><a href=\"#\" class=\"hollow button cancel_confirm\" data-close type=\"cancel\" Ok</a></div></div></div>").foundation('open');
		} else {
		    alert(data['responseJSON']['error']);
		}
                taggle.remove(tag);
            } else {
		if (modal) {
                    permissionDenied(modal);
		} else {
		    alert("Permission Denied");
		}
                taggle.remove(tag);
            }
        });
}

function del_tag(taggle, tag, modal){
    var csrftoken = getCookie('csrftoken');
    var url = $("#vul_taggs").attr("action");
    $.post(url,
           {'state': 0, 'csrfmiddlewaretoken': csrftoken, 'tag': tag, 'del_tag':true}, function (data) {
               console.log("success removing");
            })
        .fail(function (data) {
            if (data['error']) {
                alert("An error occurred while trying to delete this tag: " + data['error']);
                taggle.add(tag);
            } else {
                permissionDenied(modal);
                taggle.add(tag);
            }
        });

}


$(document).ready(function() {

    if($('#largemodal').length < 1) {
	$('body').prepend('<div class="reveal large" id="largemodal" ' +
			  'data-reveal data-close-on-click="false"></div>');
    }
    let _ = new Foundation.Reveal($('#largemodal'));
    var modal = $("#largemodal");
    
    var vul_tags = [];
    var allowed_tags = [];
    if (document.getElementById('tags')) {
        vul_tags = JSON.parse(document.getElementById('tags').textContent);
    }
    if (document.getElementById('atags')) {
	var allowed_tags = JSON.parse(document.getElementById('atags').textContent);
    }

    if (document.getElementById('vul_taggs')) {
	var taggle = new Taggle('vul_taggs', {
            tags: vul_tags,
            allowedTags: allowed_tags,
            duplicateTagClass: 'bounce',
            placeholder: ["Tag this vulnerability..."],
	    tagFormatter: function(li) {
                var node = li.querySelector('.taggle_text');
                var text = node.textContent;
                var link = '<a href="/vince/search/?q='+text+'&facet=Vuls"/>';
                $(node).wrapInner(link);
                return li;
            },
	    onTagAdd: function (event, tag) {
		if (event) {
                    add_tag(taggle, tag, modal)
		}
            },
            onBeforeTagRemove: function (event, tag) {
                if (event) {
                    del_tag(taggle, tag, modal)
                }
                return true;
            },
	});
	if (allowed_tags.length == 0) {
            taggle.disable();
	}
	autoVulTaggle(allowed_tags, taggle);
    }


    $(document).on("click", '.downloadcvefile', function(event) {
        event.preventDefault();
        window.location = $(this).attr("href");
    });
    
    $(document).tooltip({
        tooltipClass: 'tooltipster-default',
    });
	    
    /*
     $('a').each(function () {
	$(this).qtip({
            content: $(this).attr("title"),
            style: {classes: 'qtip-youtube'}
        })
     });
    */

    $(document).on("click", '.openeditmodal', function(event) {
	event.preventDefault();
	var url = $(this).attr("href")
	$.ajax({
	    url: url,
	    type: "GET",
            success: function(data) {
		modal.html(data).foundation('open');
		initiate_vul_add_form();
	    }
	});
    });
    
    var addmodal = $("#smallmodal");

    $(document).on("click", '.addvulmodal', function(event) {
	event.preventDefault();
	$.ajax({
	    url: $(this).attr("href"),
	    type: "GET",
            success: function(data) {
		modal.html(data).foundation('open');
		initiate_vul_add_form();
	    }
	});
    });

    $(document).on("click", '#reserve', function(event) {
	event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });

    $(document).on("click", '.clonevul', function(event) {
        $.ajax({
            url: "/vince/case/clonevul/" + $(this).attr("obj") + "/",
            success: function(data) {
		modal.html(data).foundation('open');
                initiate_vul_add_form();

            }
        });
    });
    
    $(document).on("click", '#cvsser', function(event) {
	event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });
    
    
    $(document).on("click", '.rmexploit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });
    
    $(document).on("click", '.addexploit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("action"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
		$( "#id_reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
		
            }
        });
    });

    $(document).on("click", '.editexploit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });

    
    $(document).on("click", '.shareexploit', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
		$("#exploits").html(data);
            }
        });
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
        return "<a href=\"" + cell.getRow().getData().edit_link+"\" class=\"openeditmodal btn-link\"><i class=\"fas fa-pencil-alt\"></i></a><button class=\"clonevul btn-link\" obj="+cell.getValue()+"><i class=\"far fa-clone\"></i></button><button class=\"deletevul btn-link\" href=\""+cell.getRow().getData().remove_link+"\"><i class=\"fas fa-trash-alt\"></i></button>";
    };



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
                addmodal.html(data).foundation('open');
            }});
    });

    $(document).on("click", '.clonevul', function(event) {
        $.ajax({
            url: "/vince/case/clonevul/" + $(this).attr("obj") + "/",
            success: function(data) {
                console.log(data["url"]);
                $.ajax({
                    url: data["url"],
                    success: function(data) {
                        modal.html(data).foundation('open');
                    }});
            }});
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
        var table = new Tabulator("#vuls-table", {
            data:data, //set initial table data
            layout:"fitColumns",
            columns:[
                {title:"ID", field:"cert_id", cellClick: vulCellClick},
                {title:"Description", field:"description", cellClick: vulCellClick},
                {title:"CVE", field:"cve", formatter:cveFormatter},
                {title:"CWE", field:"cwe", cellClick: vulCellClick},
		{title:"Exploits", field:"exploits", cellClick: vulCellClick},
                {title:"Date Added", field:"date_added", cellClick: vulCellClick},
		{title:"Tags", field:"tags", formatter:tagFormatter, width:250, cellClick:vulCellClick},
                {formatter:buttonFormatter, align:"center", field:"id"}
            ],

	});
    }

    $(document).on("click", '.viewstmt', function(event) {
        $.ajax({
            url: $(this).attr("href"),
            success: function(data) {
                modal.html(data).foundation('open');
            }});
    });

    $(document).on("click", '#copycvss', function(event) {
	event.preventDefault();
	value = $("#cvss_vector").html();
	var $temp = $("<input>");
        $("body").append($temp);
        $temp.val(value).select();
        document.execCommand("copy");
        $temp.remove();

    });

    $(document).on("click", '#delcvss', function(event) {
	event.preventDefault();
	$.ajax({
            url: $(this).attr("href"),
            success: function(data) {
                modal.html(data).foundation('open');
            }});
    });
	
    $(document).on("click", '#delssvc', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            success: function(data) {
                modal.html(data).foundation('open');
	    }});
    });	
    
    
    $(document).on("submit", '#calculatecvss', function(event) {
	event.preventDefault();
	var rv = updateScores();
	if (rv == true) {
	    var data = $('#calculatecvss').serializeArray();
	    data.push({'name':'severity', 'value': $("#cvss_severity").html()});
	    data.push({'name':'vector', 'value': $("#cvss_vector").html()});
	    data.push({'name':'score', 'value':$("#cvss_base").html()});
	    
	    addmodal.foundation('close');

	    $.ajax({
		url: $("#calculatecvss").attr("action"),
		type: "POST",
		data: data,
		success: function(data) {
		    
		}
	    });

	    $("#delcvss").removeClass("hidden");
	    
	    
	} else {
	    return false;
	}

    });

    
    
});
