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

function update_dash(divthis, table) {

    /*which stat is active? */
    var url = $(".dash_header.active").children('a').eq(0).attr("href");
    var dash_id = $(".dash_header.active").children('a').eq(0).attr('id');

    var xhr = new XMLHttpRequest();
    
    $.ajax({
        url: divthis.attr("action"),
	xhr: function() {
	    return xhr;
	},
        success: function(data) {
	    var respurl = xhr.responseURL;
	    /* determine if this is a rdirect */
	    if (respurl.includes("login")) {
		location.reload();
	    }
            divthis.html(data);
	    if (dash_id) {
		var element = document.getElementById(dash_id);
		element.parentNode.classList.add("active");
	    }
        },
    });
    
    /* update the table based on the what is active */

    if (url) {
	if (!url.includes("#")) {
	    $.ajax({
		url: url,
		success: function(data) {
		    table.setData(data);
		}
	    });
	}
    } else {
	update_tickets(table);
    }


}

function update_stats(divthis) {
    
    $.ajax({
        url: divthis.attr("action"),
	success: function(data) {
	    divthis.html(data);
	}
    });
}


function update_tickets(table) {

    $.ajax({
        url: $("#tkt-table").attr("action"),
        success: function(data) {
            table.setData(data);
        }
    });
}



$(document).ready(function() {


    $('#showcharttip').qtip({
	content: $("#duedatechart"),
        style: {classes: 'qtip-youtube'}
    });

    $('#showpubtip').qtip({
        content: $("#publishchart"),
        style: {classes: 'qtip-youtube'}
    });
    
    var cellClickFunction = function(e, cell) {
        var url_mask = "/vince/ticket/" + cell.getRow().getData().id;
        window.location = url_mask;
    };

    var ticketLinkFunction = function(cell) {
	var url_mask = "/vince/ticket/" + cell.getRow().getData().id;
        return {url: url_mask};
    }


    //Trigger setFilter function with correct parameters
    function updateFilter(){
	
	table.setFilter($("#filter-field").val(), "like", $("#filter-value").val());
    }

    //Update filters on value change
    $("#filter-field").change(updateFilter);
    $("#filter-value").keyup(updateFilter);

    //Clear filters on "Clear Filters" button click
    $("#filter-clear").click(function(){
	$("#filter-field").val("");
	$("#filter-value").val("");
	
	table.clearFilter();
    });


    var table = new Tabulator("#tkt-table", {
        layout:"fitColumns",
	placeholder:"No Tickets",
	ajaxURL:$("#ticket-title").attr('action'),
	ajaxProgressiveLoad:"scroll",
	ajaxFiltering:true,
	height:"1000px",
        columns:[
            {title:"Ticket", field:"ticket", formatter: "link", formatterParams: ticketLinkFunction, headerFilter:"input"},
            {title:"Title", widthGrow:3, field:"title", cellClick: cellClickFunction, headerFilter: "input"},
            {title:"Status", field:"status", cellClick: cellClickFunction, headerFilter:true, headerFilterParams:{"Closed":"Closed", "Open":"Open", "In progress": "In Progress"}},
	{title:"Assigned", field:"assigned_to", cellClick:cellClickFunction, headerFilter:true},
	    {title:"Resolution", field:"resolution", cellClick:cellClickFunction},
            {title:"Last Modified", field:"date", cellClick: cellClickFunction},
        ],
	
    });

    //update_tickets(table);
    
    
    $("#ticketdash").parent().addClass("active");
				    
    var caseClickFunction = function(e, cell) {
        var url_mask = cell.getRow().getData().url;
        window.location = url_mask;
    };

    var caseLinkFunction = function(cell) {
        var url_mask = cell.getRow().getData().url;
        return {url: url_mask};
    }

    var vendorTooltipFunc = function(cell) {
	return "Vendors: " + cell.getRow().getData().vendors + "\nVendors Notified: " + cell.getRow().getData().vendors_notified + "\nVendors Seen: " + cell.getRow().getData().vendors_seen;
    }

    function publicFormatter(cell, formatterParams, onRendered) {
	var publicd = cell.getRow().getData().publicdate;
	if (publicd) {
	    return "<span class=\"" + cell.getRow().getData().date_color + "\">"+ publicd + "</span>"
	}
	else {
	    if (cell.getRow().getData().date_color == "error") {
		return "<span class=\"" + cell.getRow().getData().date_color + "\">OVERDUE: "+ cell.getRow().getData().due_date + "</span>"
	    } else if (cell.getRow().getData().due_date) {
		return "<span class=\"" + cell.getRow().getData().date_color + "\">DUE: "+ cell.getRow().getData().due_date + "</span>"
	    } else {
		return "<span class=\"" + cell.getRow().getData().date_color + "\">No date set</span>"
		
	    }
	}
    }

    var dateTooltipFunc = function(cell) {
	var publicd = cell.getRow().getData().publicdate;
        if (publicd) {
            return publicd;
        } else {
	    return cell.getRow().getData().due_date;
	}
    }
    
    var case_table = new Tabulator("#case-table", {
	layout:"fitColumns",
        placeholder:"No Cases",
        ajaxURL:$("#casedash").attr('href'),
        ajaxProgressiveLoad:"scroll",
	ajaxFiltering:true,
	height:"1000px",
        columns:[
            {title:"Case ID", field:"vu", formatter: "link", formatterParams: caseLinkFunction, headerFilter:"input"},
            {title:"Title", widthGrow:3, field:"title", cellClick: caseClickFunction, headerFilter: "input"},
            {title:"Assigned", field:"assigned_to", cellClick:caseClickFunction, headerFilter:true},
	    {title:"Vendors", field: "vendors", cellClick:caseClickFunction, tooltip:vendorTooltipFunc},
	    {title:"Vuls", field: "vuls", cellClick:caseClickFunction},
	    {title:"Public", field:"due_date", cellClick:caseClickFunction, formatter:publicFormatter, tooltip:dateTooltipFunc},
	    {title:"Posts", field: "posts", cellClick:caseClickFunction},
	    {title:"VulNote", field: "vulnote", cellClick:caseClickFunction},
	    
        ],

    });
    
    $(document).on("click", '.filtercase', function(event) {
	event.preventDefault();
	var title = $(this).next().html();
	$(".chart__label.active").removeClass("active");
	$(".dash_header.active").removeClass("active");
	$(this).parent().addClass("active");
	
	table.replaceData($(this).attr("href"));
	$(".dashtkt").show();
        $(".dashpostdiv").hide();
	
	$("#ticket-title").replaceWith("<h3 id=\"ticket-title\">"+title + "</h3>");
    });


    $(document).on("click", "#casedash", function(event) {
	$(".dashtkt").hide();
        $(".dashpostdiv").show();
    });

    var lines = 12; //Choose how many lines you would like to initially show                                            
    var buttonspacing = 0; //Choose Button Spacing                                                                      
    var buttonside = 'left'; //Choose the Side the Button will display on: 'right' or 'left'                           \
                                                                                                                        
    var animationspeed = 1000; //Choose Animation Speed (Milliseconds)                                                  
    //Do not edit below                                                                                                 
    var lineheight = 0;
    if ($('.text_content').css("line-height")) {
        lineheight = $('.text_content').css("line-height").replace("px", "");
    }
    startheight = lineheight * lines;
    var shortheight = $('.textheightshort').css('max-height');
    // Instead take the max-height set on the textheightshort/textheightlong attributes                                 
    //$('.text_container').css({'max-height' : startheight });                                                          

    var buttonheight =  $('.showfull').height();
    $('div.long_text_container').css({'padding-bottom' : (buttonheight + buttonspacing ) });
    
    if(buttonside == 'right'){
        $('.showfull').css({'bottom' : (buttonspacing / 2), 'right' : buttonspacing });
    } else{
       $('.showfull').css({'bottom' : (buttonspacing / 2), 'left' : buttonspacing });
    }

    $('.moretext').on('click', function(){
        var newheight = $(this).parent('div.long_text_container').find('div.text_content').height();
	$(this).parent('div.long_text_container').find('div.text_container').animate({'max-height' : newheight }, animationspeed );
	$(this).hide().siblings('.lesstext').show();
        $(this).next().next('.scrollnext').fadeIn();

    });

    $('.lesstext').on('click', function(){
        var shortelem = $(this).parent('div.long_text_container').find('div.text_container').hasClass('textheightshort');
        var newheight = startheight;
        if (shortelem) {
            newheight = shortheight;
	}
        var h = $(this).parent('div.long_text_container').find('div.text_content').height();
        $(this).parent('div.long_text_container').find('div.text_container').animate({'max-height' : newheight }, animationspeed );
	$(this).hide().siblings('.moretext').show();
        $(this).next('.scrollnext').fadeOut();
    });

    $('div.long_text_container').each(function(){
        if( $(this).find('div.text_content').height() > $(this).find('div.text_container').height() ){
            $(this).find('.showfull.moretext').show();

        }
    });

    
});
