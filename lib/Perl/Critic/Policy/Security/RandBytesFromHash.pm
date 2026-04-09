package Perl::Critic::Policy::Security::RandBytesFromHash;

use v5.24;
use warnings;

use parent 'Perl::Critic::Policy';

use Const::Fast qw( const );
use List::Util qw( any );
use Perl::Critic::Utils qw( :severities :classification :ppi );
use Ref::Util qw( is_plain_arrayref );

our $VERSION = 'v0.1.0';

use constant DESC => 'random bytes generated using a hash';
use constant EXPL => 'A hash seeded with poor sources of entropy is still a poor source of entropy, use system entropy instead.';

use experimental qw( signatures );

sub supported_parameters { () }

sub default_severity { $SEVERITY_HIGH }

sub default_themes { 'security' }

sub applies_to { 'PPI::Token::Word' }

const my $DIGEST_REGEX => qr/\A (
        ( \w+:: )*
        ( md[2456] | sha( 1 | 224 | 256 ) | digest_data | join )
        ( _ ( hex | b64u? | base64 ) )?
        ) \z/nx;

sub violates ( $self, $elem, $ ) {

    # TODO method calls ->(hex|b64)?digest

    if ( $elem =~ $DIGEST_REGEX && is_function_call($elem) )
    {

        my @args = parse_arg_list($elem);

        if ( $self->_is_bad_seed_source( \@args ) ) {
            return $self->violation( DESC, EXPL, $elem );
        }

    }

    return ();
}

sub _is_bad_seed_source( $self, $elem ) {

    if ( is_plain_arrayref($elem) ) {
        return any { $self->_is_bad_seed_source($_) } $elem->@*;
    }

    return 0 if $elem->isa("PPI::Token::Whitespace");

    return 1
      if $elem =~ /\A ( (CORE::)?rand | (Time::HiRes::)? (time|gettimeofday|localtime|gmtime) | refaddr ) \z/nx
      && ( is_perl_builtin_with_optional_argument($elem)
        || is_function_call($elem) );

    return 1 if $elem eq '$$' && is_perl_global($elem);

    return 1 if $elem =~ /\A \{ \s* \} \z/x && $elem->isa("PPI::Structure");

    return 1 if $elem =~ /\A \[ \s* \] \z/x && $elem->isa("PPI::Structure");

    if ( $elem->isa("PPI::Structure") ) {
        return any { $self->_is_bad_seed_source($_) } $elem->children
    }
    elsif ( $elem->isa("PPI::Statement") ) {
        return any { $self->_is_bad_seed_source($_) } $elem->children
    }

    return 0;
}

1;
