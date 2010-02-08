use strict;
use warnings;
use CGI::Simple;
use POE qw(Component::FastCGI Component::Captcha::reCAPTCHA);

# Your reCAPTCHA keys from
#   https://admin.recaptcha.net/recaptcha/createsite/
use constant PUBLIC_KEY       => '<public key here>';
use constant PRIVATE_KEY      => '<private key here>';

my $captcha = POE::Component::Captcha::reCAPTCHA->spawn();

POE::Session->create(
   package_states => [
      'main' => [qw(_start _request _captcha)],
   ],
);

exit 0;

sub _start {
  my ($kernel,$session) = @_[KERNEL,SESSION];

  POE::Component::FastCGI->new(
    Port => 1027,
    Handlers => [
        [ '.*' => $session->postback( '_request' ) ],
    ]
  );

  return;
}

sub _request {
  my ($kernel,$heap) = @_[KERNEL,HEAP];
  my $request = $_[ARG1]->[0];

  my $error = undef;

  my $response = $request->make_response;
  $response->header("Content-type" => "text/html");
  my $content = <<EOT;
<html>
  <body>
    <form action="" method="post">
EOT

  if ( $request->method eq 'POST' ) {

  }

  $content .= $captcha->get_html( PUBLIC_KEY, $error );
  $content .= <<EOT;
    <br/>
    <input type="submit" value="submit" />
    </form>
  </body>
</html>
EOT

  $response->content($content);
  $response->send;
  return;
}
