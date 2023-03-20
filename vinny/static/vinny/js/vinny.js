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

function initTooltipster(element, umProfileStore, displayUserCard) {
    /*replaced to use standard jquery tooltip since plugin was failing */
    $(document).tooltip({
	items:'.user-mention, .vendor-participant',
        tooltipClass: 'tooltipster-default',
	content: function(callback) {
            var userUrl = $(this).attr('href')+"?quick=1";
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



$(document).ready(function() {
    /*$('.tooltippy').tooltipster({
	maxWidth:200});*/
    
    var simplemde = new SimpleMDE({element: $("#id_content")[0],
				 renderingConfig: {
				     singleLineBreaks: false,
				 },
				   status: false,
				   toolbar: ["bold", "italic", "heading", "|", "quote", "unordered-list", "ordered-list", "|",
					     "link", "image", "|", "preview", "side-by-side", "fullscreen", "|", {
					     name: "guide",
						 action: function openlink() {
						     var win = window.open('https://www.markdownguide.org/basic-syntax/', '_blank');
						     win.focus();
						 },
						 className: "fa fa-question-circle",
						 title: "Markdown Guide"
					     }],
				   placeholder: "Ask a question or post a reply. Use @ to tag someone in your post.",
				   autoDownloadFontAwesome: false,
				  });
    
    /* blank content on reload */
    simplemde.value("");

    // user mentions support
    simplemde.codemirror.on("keyup", function (cm, event) {
        if(event.key === "@" || (event.shiftKey && event.keyCode === 50 /* "2" key */)) {
	    CodeMirror.showHint(cm, CodeMirror.hint.alluraUserMentions, {
                completeSingle: false
	    });
        }
    });
    

    /*$(document).on("click", "#replybutton", function(event) {
	event.preventDefault();
	$('html, body').animate({scrollTop:$(document).height()}, 'slow');
	$( "#post_reply" ).slideToggle( "slow", function() {
	    // Animation complete.
	});
    });*/

    $(document).on("click", ".cancelform", function(event) {
	event.preventDefault();
	simplemde.value("");
    });


    var $modal = $('#modal');
    var $largemodal = $('#largemodal');
    $(document).on("click", ".openmodal", function(event) {
        event.preventDefault();
	$.ajax({
	    url: $(this).attr('href'),
	    type: "GET",
	    success: function(resp) {
		$modal.html(resp).foundation('open');
	    }
	});
		
    });


    $(document).on("click", ".orig_report", function(event) {
	event.preventDefault();
        $.ajax({
            url: $(this).attr('href'),
            type: "GET",
            success: function(resp) {
                $largemodal.html(resp).foundation('open');
            }
        });
    });
    
    var $uploadmodal = $("#upload-file");
    $(document).on("click", ".uploadfile", function(event) {
	event.preventDefault();
	$.ajax({
	    url: $(this).attr('href'),
	    type: "GET",
	    success: function(resp) {
		$uploadmodal.html(resp).foundation('open');
	    }
	});
    });
    function update_dropdown(dtrack,pk) {
	if((!pk) && ('group_id' in dtrack)) {
	    /* A new entry remove value from dropdown if exists */
	    group_id = dtrack['group_id'];
	    $('#trackingmodal')
		.find('select.group_id option[value="'+group_id+'"]').remove();
	    /* Hide Add Tracking if no longer needed */
	    if($('#trackingmodal').find('select.group_id option').length < 1)
		$('.addtracking').addClass('hide');
	}
    }
    function submit_tracking(event) {
	event.preventDefault();
	$uploadmodal.find(".errormsg").addClass("hidden");
	let tracker = $uploadmodal.find('.tracker').val();
	let pk = $uploadmodal.find('.track_id').val();
	let group_id = $uploadmodal.find('select.group_id').val();
	if(pk) {
	    group_id = 0;
	}
	$.post($('.updatetracking').attr('action'),
	       {tracker: tracker,
		group_id: group_id,
		case_id: $('.case_id').val(),
		pk:  pk,
		'csrfmiddlewaretoken': getCookie('csrftoken')
	       })
	    .done(function(data) {
		if("error" in data)
		    return temp_error(data.error);
		if(!("trackings" in data)) 
		    return temp_error("Data is missing");
		render_tracking(data.trackings[0]);
		update_dropdown(data.trackings[0],pk);
		$uploadmodal.foundation('close');
	    }).fail(function() {
		console.log(arguments);
		temp_error("Server Error! See Console for details");
	    });
	return false;
    }
	    
    function temp_error(msg) {
	$uploadmodal.find(".errormsg")
	    .removeClass("hidden")
	    .html(msg);
	setTimeout(function() {
	    $uploadmodal.find(".errormsg").addClass("hidden");
	},5000);
    }
    function update_tracking() {
	if($('select.group_id option').length > 0) {
	    /* Even if one group has no tracking ID show Add Tracking ID*/
	    $('.addtracking').removeClass('hide');
	}
	if(typeof(update_locales) == 'function')
	    update_locales();
	$(".modtrack").on("click", function(event) {
	    $uploadmodal.find(".errormsg").addClass("hidden");	    
            event.preventDefault(); 
	    let content = $('#trackingmodal').html();
	    $uploadmodal.html(content).foundation('open');
	    $uploadmodal.find('.updatetracking').on('submit',submit_tracking);
	    if($(this).data('pk')) {
		/* Modify tracking ID  */
		$uploadmodal.find(".track_id").val($(this).data('pk'));
		let div = $(this).closest('div.tracking');
		let tracker = div.find('.tracker').html();
		let trackorg = div.find('.trackorg').html();
		let trackorg_id = div.find('.trackorg').data('pk');
		/* Hide the organization dropdown and print the Organization's
		 name if the user is part of more than one organization*/
		$uploadmodal.find('.group_id').hide();
		if(($uploadmodal.find('.group_id option').length > 1) ||
		   ( $('.track-dynamic').length > 1) ) {
		    $uploadmodal.find('.trackorg').append(
			$('<div>')
			    .css({border: '1px solid ',
				  borderRadius: '3px',
				  padding: '4px'})
			    .text(trackorg));
		}		
		$uploadmodal.find('.tracker').val(tracker);
	    } else {
		/* Adding a new tracking ID */
		$uploadmodal.find(".track_id").val('');
	    }
	});
    }
    function render_tracking(tdata) {
	if(!("tracker" in tdata)) {
	    $('.group_id')
		.append($('<option>')
			.text(tdata.trackorg)
			.val(tdata.group_id)
		       )
	    return;
	}
	let pk = String(tdata.track_id);
	let group_id = String(tdata.group_id);
	let trackdiv = $('.trackings > .tracking.hide').clone()
	    .removeClass('hide').attr("id","tracking-" + pk)
	    .addClass('track-dynamic');
	if($('#tracking-' + pk).length < 1)
	    $('.trackings').append(trackdiv);
	trackdiv = $('#tracking-' + pk);
	trackdiv.find(".modtrack").attr("data-pk",pk);
	/* Add options for new tracking if none present
	   for this CaseMember */
	Object.keys(tdata).forEach(function(v) {
	    if(v in tdata)
		trackdiv.find("."+v).text(tdata[v]);
	});
	trackdiv.find("trackorg").attr("data-pk",group_id);
	return 1;
    }
    function get_trackings() {
	/* Vendor or Participant that can add tracking numbers */
	$.getJSON($('.updatetracking').attr('action'),
		  {"case_id": $('.case_id').val()})
	    .done(function(data) {
		if(!("trackings" in data)) 
		    return;
		let tdata = data.trackings;
		if(tdata.length < 2)
		    $('.trackorg').hide()
		else
		    $('.trackorg').show()
		for(let i=0; i<tdata.length; i++) {
		    render_tracking(tdata[i]);
		}
		update_tracking();
	    }).fail(function() {
		console.log(arguments);
	    });
    }
    if($('.trackings').length > 0) {
	get_trackings();
    }


    $(document).on("click", ".mutecase", function(event) {
	event.preventDefault();
	var csrftoken = getCookie('csrftoken');
	var data = {'csrfmiddlewaretoken': csrftoken};
	var post = $.post($(this).attr("href"), data);
	var button = $(this);
	post.done(function(data) {
	    button.html(data["button"]);
	});
    });
    
    $(document).on("submit", "#postform", function(event) {
	// Get some values from elements on the page:
	event.preventDefault();
	var content = simplemde.value();
	if (content == "") {
	    return false;
	}
	var paginate_by =  $("#paginate_by").text();
	$('#sendbutton').prop('disabled', true);
	var $form = $( this );
	var url = $(this).attr( "action" );
	var csrftoken = getCookie('csrftoken');
	var data = {'content': content, 'csrfmiddlewaretoken': csrftoken, 'paginate_by': paginate_by};
	var reload_pinned = false;
	if ($("#reply_to").length) {
	    data["reply_to"] = $("#reply_to").val();
	    if ($("#reply_to").attr("name") == "reply_to_pinned") {
		reload_pinned = true;
		data["pinned"] = 1;
	    }
	}
	// Send the data using post
	var posting = $.post( url, data );
	
	// Put the results in a div
	posting.done(function( data ) {
	    simplemde.value("");
	    var reload_type = "#allposts";
	    if (reload_pinned) {
		reload_type = "#pinnedposts";
	    }
	    $('#sendbutton').prop('disabled', false);
	    $(reload_type).empty().append( data );
	    $(reload_type).foundation();
	    /* reload plugins */
	    $('html, body').animate({scrollTop:$(reload_type).offset().bottom}, 'slow');
	    initTooltipster(".user-mention:not(.tooltipstered)", umProfileStore, displayUserCard);
	    /* remove reply if present */
	    if (document.contains(document.getElementById("reply_to"))) {
		document.getElementById("reply_to").remove();
	    }
	    //$( "#post_reply" ).slideToggle( "slow", function() {
        //});
	});

    });

    var simplemdeedit = null;
    
    $(document).on("submit", ".editpostform", function(event) {
	event.preventDefault();
	var url = $(this).attr("action");
	var csrftoken = getCookie('csrftoken');
        var data = {'post': simplemdeedit.value(), 'csrfmiddlewaretoken': csrftoken};
        // Send the data using post
        var posting = $.post( url, data );

        // Put the results in a div
        posting.done(function( data ) {
	    location.reload();
	});
    });


    $(document).on("click", ".canceleditpost", function(event) {
	location.reload();
    });
    

    $(document).on('click', 'a.edit-post', function() {
	var post_url = $(this).parent().parent().parent().next().find('.editcontent').attr("post_url");
	$(this).parent().parent().parent().next().find('.postcontent').toggle();
	var edit_block = $(this).parent().parent().parent().next().find('.editcontent');
	edit_block.toggle();
	var text_block = "#id_post_" + $(this).attr("item");
	$.ajax({
	    url: post_url,
	    success: function(data) {
		$(edit_block).html(data);
		simplemdeedit = new SimpleMDE({element: $(text_block)[0],
					     renderingConfig: {
						 singleLineBreaks: false,
					     },
					     autoDownloadFontAwesome: false,
					    });
	    }
	});

    });

    $(document).on('click', 'a.remove-post', function() {
	event.preventDefault();
	var url = $(this).attr("action");
	$.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                $modal.html(data).foundation('open');
            }
        });
    });

    $(document).on('click', 'a.pin-post', function() {
        event.preventDefault();
        var url = $(this).parent().parent().parent().next().find('.editcontent').attr("post_url");
        var csrftoken = getCookie('csrftoken');
        var data = {'id': $(this).attr("item"), 'pin': 1, 'csrfmiddlewaretoken': csrftoken};
        // Send the data using post
        var posting = $.post( url, data );
        // Put the results in a div                                                                                                                                      
        posting.done(function( data ) {
            location.reload();
        });
    });


    $(document).on('click', '.reply-to-post', function() {
	var post = $(this).parent().parent().parent().find('.post_author');
	var lines = post.text().trim(); /*.split('\n');*/
	var post_id = $(this).attr("post_id");
	/*$("#post_reply").slideToggle( "slow", function() {});*/
	$('html, body').animate({scrollTop:$(document).height()}, 'slow');
	/*var newpost = lines.map(function(element) { return '> ' + element; });
	  simplemde.value(newpost.join('\n'));*/
	if ($(this).hasClass("pinned")) {
	    $('<input>', {
            type: 'hidden',
            id: 'reply_to',
            name: 'reply_to_pinned',
            value: post_id
        }).appendTo('#postform');

	} else {
	$('<input>', {
	    type: 'hidden',
	    id: 'reply_to',
	    name: 'reply_to',
	    value: post_id
	}).appendTo('#postform');
	}
	simplemde.value('@'+lines);
    });


    $(document).on('click', 'a.show-diff', function() {
	var url = $(this).attr("diff_url");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
		$modal.html(data).foundation('open');
            }
        });
    });


    $(document).on("submit", "#updatestatus", function(event) {
        // Get some values from elements on the page:                                                                                                             
        event.preventDefault();
        var $form = $( this );
        var url = $(this).attr( "action" );

        var csrftoken = getCookie('csrftoken');
        var data = $(this).serializeArray();
        // Send the data using post
        var posting = $.post( url, data );

        // Put the results in a div
        posting.done(function( data ) {
            $( "#updatestatuspanel" ).toggle();
	    $( "#thankspanel" ).toggle();
        });

    });

    $('#nothanks').on('click', function() {
	$( "#thankspanel" ).slideToggle( "slow", function() {
        });
    });
    
    $('input.check').on('change', function() {
	var c = $(this).attr("class");
	c = c.replace("check ", ".");
	$(c).not(this).prop('checked', false);  
    });

    
    $(document).on("click", ".file-remove", function(event) {
	event.preventDefault();
        var url = $(this).attr("href");
        $.ajax({
            url: url,
            type: "GET",
            success: function(data) {
                $modal.html(data).foundation('open');
            }
        });
    });
    
    $(document).on("click", "#downloadics", function(event) {
	var cal = ics($("#uid").text());
	var publishdate = $("#publishdate").text();
	var title = $("#case_title").text();
	cal.addEvent(title + " public (tentative)", title, "Pittsburgh, PA", publishdate, publishdate);
	cal.download();
    });


    var umProfileStore = {};
    
    var displayUserCard = function(instance, data) {
	instance.content(data);
    }

    
    initTooltipster(".user-mention", umProfileStore, displayUserCard);
    initTooltipster(".vendor-participant", umProfileStore, displayUserCard);
    
    /*
    $(".vendor-participant").tooltipster({
	animation: 'fade',
        delay: 200,
        theme: 'tooltipster-default',
        trigger: 'hover',
        position: 'top',
	iconCloning: false,
        maxWidth: 400,
        contentAsHTML: true,
	interactive: true,
        content: 'Loading...',
        functionReady: function (instance, helper) {
            var self = $(helper.origin);
            var userUrl = self.attr('href')+"?quick=1";
            if(umProfileStore.hasOwnProperty(userUrl)){
                displayUserCard(instance, umProfileStore[userUrl]);
                // load from cache                                             
            }
            else {
                $.get(userUrl, function(data) {
                    umProfileStore[userUrl] = data;
                    return displayUserCard(instance, data);

                });
            }
        }
    });
*/
    
    $(document).on("click", ".loadmore", function(event) {
	var $form = $("#postform");
        var url = $form.attr( "action" );
	var nextpostpage = $("#nextpostpage").text();
	var paginate_by = $("#paginate_by").text();
	if (nextpostpage) {
	    nextpostpage = parseInt(nextpostpage);
	} else {
	    nextpostpage = 2;
	}
        var csrftoken = getCookie('csrftoken');
	$.ajax({
	    url: url+"?page="+nextpostpage+"&paginate_by="+paginate_by,
	    beforeSend:function(){
                $(".loadmore").html("<h4>Loading...</h4>");
            },
            success: function( data ) {
		$(".loadmore").hide();
		$("#allposts").prepend(data);
		$("#nextpostpage").text(nextpostpage+1);
		/* reload plugins */
		initTooltipster(".user-mention:not(.tooltipstered)", umProfileStore, displayUserCard);
		$("#allposts .dropdown-pane").foundation();
            }
	});
    });


    
    
    $(document).on("click", ".loadreply", function(e) {
	$(this).parent().parent().next().children(".hidereply").toggle();
	$(this).toggle();
        $(this).next('.collapsereply').toggle();
    });

    $(document).on("click", ".collapsereply", function(e) {
	$(this).parent().parent().next().children(".hidereply").toggle();
        $(this).toggle();
	$(this).siblings('.loadreply').toggle();
    });

    $(document).on("click", ".expandreplies", function(e) {
	e.preventDefault();
	$(this).hide();
	$("#showall").show();
	/*$(this).text($(this).text() == 'Show all' ? 'Collapse all' : 'Show all');
        $('.loadreply').each(function() {
	    $(this).click();
	    });*/
	var $form = $("#postform");
        var url = $form.attr( "action" );
        var csrftoken = getCookie('csrftoken');
        $.ajax({
            url: url+"?no_page=1",
            beforeSend:function(){
                $(".loadmore").html("<h4>Loading...</h4>");
            },
            success: function( data ) {
                $(".loadmore").hide();
		$("#allposts").html(data);
		/* reload plugins */
                initTooltipster(".user-mention:not(.tooltipstered)", umProfileStore, displayUserCard);
                $("#allposts .dropdown-pane").foundation();
            }
	});

    });
    
});
