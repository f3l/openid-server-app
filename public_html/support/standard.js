var openid = {};
openid.events = {};

openid.events.login = function (event, form) {
    var username_obj = jQuery(form).find('input[name="username"]');
    var password_obj = jQuery(form).find('input[name="password"]');
    var remember_obj = jQuery(form).find('input[name="remember"]');

    var submit_obj = jQuery(form).find('input[name="submit"]');
    var target_obj = jQuery(event.originalEvent.explicitOriginalTarget);
    var target = target_obj.attr('name');

    // if logging in then make sure the user has entered stuff
    if (target === 'cancel') {
        submit_obj.val('cancel');
    } else {
        submit_obj.val('login');
        var username = jQuery.trim(username_obj.val());
        var password = jQuery.trim(password_obj.val());

        if (!username) {
            alert('You must enter a username.');
            username_obj.focus();
            event.preventDefault();
            return;
        }
        if (!password) {
            alert('You must enter a password.');
            password_obj.focus();
            event.preventDefault();
            return;
        }
    }

    // disable the cancel and submit buttons
    jQuery(form).find('input[type="submit"]').attr('disabled', 'disabled');
}

openid.events.trust = function (event, form) {
    var submit_obj = jQuery(form).find('input[name="submit"]');
    var target_obj = jQuery(event.originalEvent.explicitOriginalTarget);
    var target = target_obj.attr('name');

    // if logging in then make sure the user has entered stuff
    if (target === 'cancel') {
        submit_obj.val('cancel');
    } else {
        submit_obj.val('trust');
    }

    // disable the cancel and submit buttons
    jQuery(form).find('input[type="submit"]').attr('disabled', 'disabled');
}

openid.events.remove = function (event, form) {
    event.preventDefault();

    var remove = new Array();
    jQuery(form).find('input[type="checkbox"]:checked').each(function (index, item) {
        remove.push(jQuery(item).val());
    });

    jQuery.ajax({
        url: window.location,
        type: 'POST',
        dataType: 'xml',
        data: {
            'submit': true,
            'remove': remove
        },
        error: function () {
            alert('There was a server error when trying to remove sites.');
        },
        success: function (response) {
            var errors = false;
            jQuery(response).find('errors > error').each(function (index, item) {
                alert(jQuery(item).text());
                errors = true;
            });

            if (!errors) {
                var value = jQuery(response).find('content').text();
                if (value === 'success') {
                    jQuery.each(remove, function (index, item) {
                        jQuery('#trusted-' + item).find('input[type="checkbox"]').removeAttr('checked').attr('disabled', 'disabled');
                        jQuery('#trusted-' + item).removeClass('highlight');
                        jQuery('#trusted-' + item).css({
                            'fontStyle': 'italic',
                            'color': '#666666'
                        });
                        jQuery('#trusted-' + item).find('div.name label').css('textDecoration', 'line-through');
                    });
                } else {
                    alert('Unknown response from the server.');
                }
            }
        }
    });
}

openid.select = function (e, action) {
    var form = jQuery(e).closest('form');
    if (action === 'all') {
        jQuery(form).find('input[type="checkbox"]:not(:disabled)').each(function (index, item) {
            jQuery(this).attr('checked','checked');
            jQuery(this).closest('div.row').addClass('highlight');
        });
    }
    if (action === 'none') {
        jQuery(form).find('input[type="checkbox"]:checked').removeAttr('checked');
        jQuery(form).find('div.row').removeClass('highlight');
    }
}

openid.checked = function (event, checkbox) {
    if (jQuery(checkbox).is(':checked')) {
        jQuery(checkbox).closest('div.row').addClass('highlight');
    } else {
        jQuery(checkbox).closest('div.row').removeClass('highlight');
    }
}

