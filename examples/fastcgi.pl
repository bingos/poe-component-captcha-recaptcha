use strict;
use warnings;
use POE qw(Component::FastCGI Component::Captcha::reCAPTCHA);

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

  my $response = $request->make_response;
  $response->header("Content-type" => "text/html");
  $response->content("A page");
  $response->send;
}
