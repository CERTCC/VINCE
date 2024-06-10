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

function nextPage(page) {
    $("#searchresults").load("/vince/ticket/results/?page=" + page);
}


function reloadSearch() {
    $.ajax({
        url: "/vince/ticket/results/",
        success: function(data) {
            $("#searchresults").html(data);
        }
    });
}

function nextTickets(page) {
    var url = "/vince/ticket/results/";
    $("#id_page").val(page);
    $.ajax({
        url: url,
        type: "POST",
        data: $('#searchform').serialize(),
        success: function(data) {
            $("#searchresults").html(data);
        }
    });

}
function searchTickets(e) {
    if (e) {
	    e.preventDefault();
    }

    $("#id_page").val("1");

    let url = "/vince/ticket/results/";
    lockunlock(true,'div.mainbody,div.vtmainbody','#searchresults');
    window.txhr = $.ajax({
	    url: url,
	    type: "POST",
	    data: $('#searchform').serialize(),
	    success: function(data) {
	        lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
	        $("#searchresults").html(data);
	    },
	    error: function() {
	        lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
	        console.log(arguments);
	        alert("Search failed or canceled! See console log for details.");
	    },
	    complete: function() {
	        /* Just safety net */
	        lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
	        window.txhr = null;
	    }
    });
}
async function close_tickets(search) {
    if (!search){
	    search = "Email Bounce";
    }
    let morepages = 1;
    let csrf = getCookie('csrftoken');
    let enddate = new Date().toISOString();
    enddate = enddate.replace(/T.*/,'');
    let pbody = "csrfmiddlewaretoken=" + csrf + "&new_status=4";
    let hm = get_modal();
    let postbody = "csrfmiddlewaretoken="+csrf+"&new_status="+4
    let hdr = {'Content-type': 'application/x-www-form-urlencoded'};
    hm.append("<h4> Do not close this window </h4>");
    hm.append("<p> See Javascript console log for any failures</p>");
    hm.append("<ul class='tempul'><li><h5>Starting Tickets</h5></li></ul>");
    let ul = hm.find('.tempul');
    ul.find("li > h5").append(" for <i>"+search+"</i> ");
    while(morepages > 0) {
	    await $.post('/vince/ticket/results/', {
            csrfmiddlewaretoken: csrf,
		    owner: $('#searchform').serializeArray().filter(x => x.name == "owner")[0].value,
		    tag: "",
    		page: 1,
	    	datestart:"2000-01-01",
		    status: 1,
            dateend: enddate,
		    wordSearch: search
        }, function(d) {
            let reader = $($.parseHTML(d));
            let total = parseInt(reader.find('#resultTotal').html())
            let els = reader.find('.vulnerability-list a');
            morepages = total - els.length;
            if (els.length < 1) {
                ul.append("<li><h5>Nothing found to close!</h5></li>");
                morepages = 0;
                return;
            }
            ul.append("<li>Closing tickets <span class='mc'></span> "+
                "of total ["+total+"] </li>");
            els.each(async function(i,x) {
                let si = String(i+1);
                ul.append($("<li>").addClass("sm " + si ).html("Closing " + si + " Ticket </li>"));
                let csrf = getCookie('csrftoken');
                let req = new Request(x.href+"update/", {redirect: 'manual'});
                await fetch(req, { 
                    method:"POST",
                    headers: hdr,
                    body: pbody 
                }).then(function(b) {
                    hm.find('li.sm'+si).html("Complete " +
                        b.text()) 
                });
            
            });
	    });
    }
    finish_modal(hm);
}


$(document).ready(function() {

    $(document).on("click", '.search_page', function(event) {
    	let page = $(this).attr('next');
	    nextPage(page);
    });


    $(document).on("click", '.removetag', function(event) {
    	event.preventDefault();
	    window.location = window.location.href.split("?")[0];
    });
    
    $(document).on("click", '.search_notes', function(event) {
	    let page = $(this).attr('next');
	    nextTickets(page);
    });
    
    let input = document.getElementById("id_wordSearch");
    if (input) {
	    input.addEventListener("keydown", function(event) {
	        if (event.keyCode == 13) {
		        searchTickets(event);
	        }
	    });
    }

    searchTickets();

    let form = document.getElementById('searchform');
    if (form) {
        if (form.attachEvent) {
            form.attachEvent("submit", searchTickets);
        } else {
            form.addEventListener("submit", searchTickets);
        }
    }

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("#id_status input[type=checkbox]").prop('checked', $(this).prop('checked'));
    	searchTickets();
    });

    $("#filter_by_dropdown_select_all_1").click(function(){
        $("#id_owner input[type=checkbox]").prop('checked', $(this).prop('checked'));
	    searchTickets();
    });

    $("#filter_by_dropdown_select_all_2").click(function(){
	    $("#id_queue input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTickets();
    });

    $("#filter_by_dropdown_select_all_3").click(function(){
	    $("#id_case input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTickets();
    });

    $("#filter_by_dropdown_select_all_4").click(function(){
	    $("#id_team input[type=checkbox]").prop('checked', $(this).prop('checked'));
	    searchTickets();
    });

    $(document).on("click", '.removestatus', function(event) {
        event.preventDefault();
        let val = $(this).attr("val");
        $("#id_status input[value="+val+"]").prop('checked', false);
        searchTickets();
    });

    $(document).on("click", '.removeowner', function(event) {
	    event.preventDefault();
	    let val = $(this).attr("val");
        $("#id_owner input[value="+val+"]").prop('checked', false);
	    searchTickets();
    });

    $(document).on("click", '.removequeue', function(event) {
	    event.preventDefault();
        let val = $(this).attr("val");
        $("#id_queue input[value="+val+"]").prop('checked', false);
	    searchTickets();
    });

    $(document).on("click", '.removeteam', function(event) {
        event.preventDefault();
	    let val = $(this).attr("val");
        $("#id_team input[value="+val+"]").prop('checked', false);
        searchTickets();
    });
    
    $("input[id^='id_status_']").change(function() {
	    searchTickets();
    });

    $("#id_queue").change(function() {
	    searchTickets();
    });

    $("#id_case").change(function() {
	    searchTickets();
    });

    $("#id_team").change(function() {
        searchTickets();
    });

    $("input[id^='id_owner_']").change(function() {
	    searchTickets();
    });
    

    /*$.getJSON("/vuls/ajax_calls/search/", function(data) {
        vend_auto(data);
    });*/

    let dateFormat = "yy-mm-dd"

    let from = $( "#id_datestart" ).datepicker({
        defaultDate: "+1w",
        changeMonth: true,
        changeYear: true,
        dateFormat: dateFormat,
        numberOfMonths: 1,
        maxDate: "+0D"
    }).on( "change", function() {
        /*to.datepicker( "option", "minDate", getDate( this ) );*/
	    searchTickets();
    })
    
	let to = $( "#id_dateend" ).datepicker({
        defaultDate: "+1w",
        changeMonth: true,
        changeYear: true,
        dateFormat: dateFormat,
        numberOfMonths: 1,
        maxDate: "+0D"
	}).on( "change", function() {
        from.datepicker( "option", "maxDate", getDate( this ) );
	    searchTickets();
	});

    $('input').qtip({
        show: {
            ready: true
        },
        content: {
            attr: 'errormsg'
        },
        position: {
            my: 'top center',
            at: 'top center',
            target: this
        },
        style: {
            classes: 'qtip-red qtip-bootstrap'
        }

    });

    function getDate( element ) {
    	let date;
	    try {
            date = $.datepicker.parseDate( dateFormat, element.value );
	    } catch( error ) {
            date = null;
	    }

	    return date;
    }
});
