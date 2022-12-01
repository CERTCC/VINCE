/*#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
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

function loadEditForm(id, panel) {
    var url = "/vince/email_template/edit/"+id+"/";
    $.ajax({
	url: url,
	success: function(data) {
	    $(panel).html(data);
	}
    });
}


function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?                                                         
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

function searchTmpls(e, tablet) {
    var csrftoken = getCookie('csrftoken');

    if (e) {
        e.preventDefault();
    }
    
    var url = $("#filter_templates").attr("href");
    var owner = $("input[id^='id_owner_']:checked").val();
    lockunlock(true,'div.vtmainbody','#template-table');
    window.txhr = $.ajax({
        url : url,
        type: "POST",
        data: {"keyword": $("#filter_templates").val(),
               "owner": owner,
               "csrfmiddlewaretoken": csrftoken
              },
        success: function(data) {
	    lockunlock(false,'div.vtmainbody','#template-table');	    
	    tablet.replaceData(data['templates'])
        },
	error: function() {
	    lockunlock(false,'div.vtmainbody','#template-table');
            console.log(arguments);
           alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
	    lockunlock(false,'div.vtmainbody','#template-table');
            window.txhr = null;
        }
    });
}



$(document).ready(function() {
    var filter_msg = document.getElementById("filter_templates");
    if (filter_msg) {
        filter_msg.addEventListener("keyup", delaySearch(function(event) {
            searchTmpls(event, tablet);	    
        },1000));
    }

    $("input[id^='id_owner_']").change(function() {
        searchTmpls(null, tablet);
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTmpls(null, tablet);

    });
    

    var buttonFormatter = function(cell,  formatterParams, onRendered){
	return "<a href=\"/vince/email_template/edit/"+cell.getValue()+"\" title=\"edit template\" class=\"edittmpl btn-link\"><i class=\"fas fa-pencil-alt\"></i></a><button class=\"clonetmpl btn-link\" obj="+cell.getValue()+"><i class=\"far fa-clone\" title=\"clone template\"></i></button><button class=\"deletetmpl btn-link\" obj="+cell.getValue()+"><i class=\"fas fa-trash-alt\" title=\"delete template\"></i></button>";
    };

    if (document.getElementById('templates')) {
	var data = JSON.parse(document.getElementById('templates').textContent);
    }

    var cellClickFunction = function(e, cell) {
	var url_mask = "/vince/email_template/edit/" + cell.getRow().getData().id;
	$.ajax({
            url: url_mask,
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    };

    
    $(document).on("click", ".edittmpl", function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                addmodal.html(data).foundation('open');
            }
        });
    });
    
    if (data) {
	/* table is an inbuilt function in Safari */
	var tablet = new Tabulator("#template-table", {
        data:data, //set initial table data          
            layout:"fitColumns",
            columns:[
		{title:"Name", field:"name", cellClick: cellClickFunction},
		{title:"Subject", field:"subject", cellClick: cellClickFunction},
		{title:"Date Modified", field:"modified", cellClick: cellClickFunction},
		{title:"Locale", field:"locale", cellClick: cellClickFunction},
		{title:"Added By", field:"user", cellClick: cellClickFunction},
		{formatter:buttonFormatter, align:"center", field:"id"}
            ],
	    
	});
   }

    var addmodal = $("#add_case_template");

    $(document).on("click", "#new_template", function(event) {
	event.preventDefault();
	$.ajax({
            url: $(this).attr("action"),
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
	    }
	});
    });


    var deletemodal = $("#delete_template");
    $(document).on('click', '.deletetmpl', function(event) {
	event.preventDefault();
	var obj = $(this).attr("obj");
	$.ajax({
            url: "/vince/email_template/delete/"+obj,
            type: "GET",
            success: function(data) {
                deletemodal.html(data).foundation('open');
            }
        });
    });

    $(document).on('click', '.clonetmpl', function(event) {
	event.preventDefault();
	var obj = $(this).attr("obj");
        $.ajax({
            url: "/vince/email_template/clone/"+obj+"/",
            type: "GET",
            success: function(data) {
		addmodal.html(data).foundation('open');
            }
        });
    });

    
});
	    
