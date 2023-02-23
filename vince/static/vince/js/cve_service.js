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


$(document).ready(function() {
    function searchCVEs(e) {
	if (e) {
            e.preventDefault();
	}
	var url = $("#search").attr("action");
	lockunlock(true,'div.mainbody,div.vtmainbody','#cve-table');
	window.txhr = $.ajax({
            url: url,
            type: "POST",
            data: $('#search').serialize(),
            success: function(data) {
		tablet.clearData();
		$("#searchresults").html(data);
		var data = JSON.parse(document.getElementById('cve_data').textContent);
		tablet.replaceData(data);
            },
	    error: function() {
		lockunlock(false,'div.mainbody,div.vtmainbody','#cve-table');
		console.log(arguments);
		alert("Search failed or canceled! See console log for details.");
            },
            complete: function() {
		/* Just safety net */
		lockunlock(false,'div.mainbody,div.vtmainbody','#cve-table');
		window.txhr = null;
            }
	});
    }

    var modal = $("#smallmodal");


    $(document).on("click", '#reserve', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            }
        });
    });

    $(document).on("click", '#viewkey', function(event) {
        event.preventDefault();
        $.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            }
        });
    });
    
    
    $(document).on("click", '.viewdetail', function(event) {
	event.preventDefault();
	$.ajax({
            url: $(this).attr("href"),
            type: "GET",
            success: function(data) {
                modal.html(data).foundation('open');
            }
        });
    });
    
    $(document).on("click", '.query', function(event) {
	event.preventDefault();
	var url = $(this).attr("href");

	$('.query').each(function() {
	    $(this).removeClass('active');
	});
	
	$(this).addClass('active');

	$(".loading").removeClass('hidden');
	
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$(".loading").addClass('hidden');
		$("#results").html(data);
            },
            error: function(xhr, status) {
                permissionDenied(modal);
            }
        });

    });

    function linkClickFunction(cell, formatterParams, onRendered) {
        var url_mask = cell.getRow().getData().cve_link;
        return "<a href=\""+url_mask+"\" class=\"viewdetail\">"+cell.getRow().getData().cve_id+"</a>";
    }

    function caseClickFunction(cell, formatterParams, onRendered) {
	var url_mask = cell.getRow().getData().vul;
	if (url_mask) {
	    return "<a href=\""+url_mask+"\">"+cell.getRow().getData().case+"</a>";
	} else {
	    return "";
	}
    }
    
    if (document.getElementById('cve_data')) {
        var data = JSON.parse(document.getElementById('cve_data').textContent);
	/* table is inbuilt function in Safari */
        var tablet = new Tabulator("#cve-table", {
            data:data,
            layout:"fitColumns",
            placeholder: "No CVEs reserved",
            tooltipsHeader:true,
            columns:[
                {title:"ID", formatter:linkClickFunction, field:"cve_id"},
                {title:"Date Added", field:"reserved"},
		{title:"State", field:"state"},
		{title:"Reserved by", field:"user"},
		{title:"VINCE Case", field:"vul", formatter:caseClickFunction},
            ],

        });
    }
    
    $(document).on("click", '.delete-btn', function(event) {
	event.preventDefault();
	var url = $(this).attr("action");
	
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		modal.html(data).foundation('open');
            },
	    error: function(xhr, status) {
		permissionDenied(modal);
	    }
	});
    });

    var input = document.getElementById("id_wordSearch");
    if (input) {
        input.addEventListener("keydown", function(event) {
            if (event.keyCode == 13) {
                searchCVEs(event);
            }
        });
    }
    
    var year_input = document.getElementById("id_year");
    if (year_input) {
        year_input.addEventListener("keydown", function(event) {
            if (event.keyCode == 13) {
                searchCVEs(event);
            }
        });
    }

    $(document).on("click", "#id_vince", function(event) {
	searchCVEs();
    });
    
});

