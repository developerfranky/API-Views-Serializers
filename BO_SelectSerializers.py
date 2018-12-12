from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.core.paginator import EmptyPage
from django.db.models import Q

from rest_framework import pagination, exceptions
from rest_framework.response import Response
from rest_framework.validators import UniqueValidator

from api.fields import serializers
from django.contrib.auth import authenticate

from login.models import Group, Profile, FCMID

from home.models import ItemAddress, ItemCategory, ItemBookmark, Item, ItemImage, ItemStatus, \
    FeaturedCategory, ItemDescriptionSearchModel, MessageThread, SingleMessage, ItemLockout, \
    Transaction, TransactionReview, BorrowRequest

from django.utils.translation import ugettext_lazy

from tagging.models import Tag, TaggedItem

from paypalrestsdk import Payment, ResourceNotFound

from geopy.geocoders import GoogleV3
from geopy import geocoders

from borrowonce import settings

gn = geocoders.GeoNames(username=settings.GEONAMES_USERNAME)
geocoder = GoogleV3(api_key=settings.GOOGLE_API_KEY)

User = get_user_model()



import logging
logger = logging.getLogger(__name__)



def email_exists(email):
    try:
        _ = User.objects.get(email=email.lower())
        raise serializers.ValidationError('User exists.')
    except User.DoesNotExist:
        pass


def username_exists(username):
    try:
        _ = User.objects.get(username=username.lower())
        raise serializers.ValidationError('User exists.')
    except User.DoesNotExist:
        pass


class FeaturedCategorySerializer(serializers.ModelSerializer):
    thumbnail = serializers.SerializerMethodField()

    def get_thumbnail(self, obj):
        try:
            return obj.avatar.url
        except (AttributeError, ValueError):
            return "/static/img/squarelogo.png"

    def get_distance(self, obj):
        try:
            return obj.get_proximity(self.context['location']['longitude'],
                                     self.context['location']['latitude'])
        except KeyError:
            return False

    def get_ending_date_formatted(self, obj):
        # Nov. 15, 2015, midnight
        if obj.ending_date:
            return obj.ending_date.strftime("%b %d, %Y")
        return ""

    class Meta:
        model = FeaturedCategory
        fields = ('id', 'search_term', 'featured_title', 'thumbnail', 'tag_list', 'keywords', 'category')


class ItemStubSerializer(serializers.ModelSerializer):
    distance = serializers.SerializerMethodField()
    ending_date_formatted = serializers.SerializerMethodField()
    bookmarked = serializers.SerializerMethodField()
    date_created = serializers.DateTimeField()
    thumbnail = serializers.SerializerMethodField()

    tags = serializers.SlugRelatedField(
        many=True,
        slug_field='name',
        required=False,
        read_only=True
    )

    def get_distance(self, obj):
        try:
            return obj.get_proximity(
                self.context['location']['latitude'],
                self.context['location']['longitude']
            )
        except KeyError:
            return ''

    def get_ending_date_formatted(self, obj):
        # Nov. 15, 2015, midnight
        if obj.ending_date:
            return obj.ending_date.strftime("%b %d, %Y")
        return ""

    def get_thumbnail(self, obj):
        if obj.main_image and obj.main_image.listing_thumbnail:
            return obj.main_image.listing_thumbnail.url
        else:
            return "/static/img/squarelogo.png"

    def get_bookmarked(self, obj):
        try:
            user = self.context['user']
            
            if user.bookmarks.filter(item__id=obj.id).exists():
                return True
        except:
            pass
        return False

    class Meta:
        model = Item
        fields = ('id', 'slug', 'title', 'price_per_day', 'distance', 'ending_date_formatted', 'thumbnail', 'tags',
                  'date_created', 'bookmarked')


class SearchSerializer(serializers.Serializer):
    tags = serializers.CharField(required=False, write_only=True)
    description = serializers.BooleanField(default=False)
    keywords = serializers.CharField(required=False, write_only=True)
    category = serializers.IntegerField(required=False, write_only=True)
    sort_by = serializers.ChoiceField(write_only=True, default=False, choices=("newest", "closest"))
    results = serializers.ListField(child=ItemStubSerializer(), read_only=True)
    longitude = serializers.FloatField(required=False)
    latitude = serializers.FloatField(required=False)
    zipcode = serializers.CharField(required=False)
    distance = serializers.IntegerField(default=0)

    def validate(self, attrs):

        if not (('tags' in attrs) | ('keywords' in attrs) | ('category' in attrs)):
            msg = ugettext_lazy('Must supply one of a tag, keyword, or category_id')
            raise exceptions.ValidationError(msg)
        return attrs

    def create(self, validated_data):
        
        results = []
        params = {}
        category = ''
        location = None

        if 'category' in validated_data:
            params['category_id'] = validated_data['category']
            category = validated_data['category']

        if 'price' in validated_data:
            params['price'] = validated_data['price']

        if 'distance' in validated_data:
            params['distance'] = validated_data['distance']

        if 'lat' in validated_data and 'lon' in validated_data:
            params['lat'] = validated_data['lat']
            params['lon'] = validated_data['lon']

            # I know, it is probably unnecessary but it's to maintain compatibility with Ryans code.
            validated_data['latitude'] =  params['lat']
            validated_data['longitude'] =  params['lon']

        if 'zipcode' in validated_data:  
            params['zipcode'] = validated_data['zipcode']
            try:
                location = gn.geocode(params['zipcode'] + ", USA")
                validated_data['latitude'] =  location.latitude
                validated_data['longitude'] =  location.longitude
            except:
                location = None

        if 'keywords' in validated_data:
            params['keywords'] = validated_data['keywords']

        if 'tags' in validated_data:
            params['tags'] = validated_data['tags']

        results = Item.objects.get_items(**params)

        context = {
            'user':self.context['request'].user,
        }

        try:
            location = {
                'longitude': validated_data['longitude'],
                'latitude': validated_data['latitude']
            }
        except:
            location = None

        print('location')
        print(location)

        if location:
            context['location'] = location

        items = ItemStubSerializer(
            results, 
            many=True, 
            # required=False, 
            context=context
            
        )

        self.validated_data['results'] = items.data
        return items


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})

    def validate(self, attrs):
        username = attrs.get('username').strip().lower()
        attrs['password'] = attrs.get('password').strip()
        User = get_user_model()
        try:
            user = User.objects.get(Q(username=username) | Q(email=username))
            attrs['username'] = user.username
        except User.DoesNotExist:
            msg = ugettext_lazy('User does not exist.')
            raise exceptions.ValidationError(msg)
        if user:
            if not user.is_active:
                msg = ugettext_lazy('User account is disabled.')
                raise exceptions.ValidationError(msg)
        self.user = user
        return attrs

    def create(self, validated_data):
        user = authenticate(username=validated_data['username'], password=validated_data['password'])
        if not user:
            msg = ugettext_lazy('User is not authenticated')
            raise exceptions.ValidationError(msg)
        return user

class CreateUserSerializer(serializers.Serializer):
    id = serializers.ReadOnlyField()  # Note: `Field` is an untyped read-only field.
    username = serializers.CharField(required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        User = get_user_model()
        try:
            _ = User.objects.get(email=email)
            msg = ugettext_lazy('Email already exists.')
            raise exceptions.ValidationError(msg)
        except User.DoesNotExist:
            pass
        try:
            _ = User.objects.get(username=username)
            msg = ugettext_lazy('Username already exists.')
            raise exceptions.ValidationError(msg)
        except User.DoesNotExist:
            pass

        return attrs

    def create(self, validated_data):
        User = get_user_model()
        _ = User.objects.create_user(validated_data['username'], validated_data['email'], validated_data['password'])
        user = authenticate(username=validated_data['username'], password=validated_data['password'])
        return user



class ItemImageSerializer(serializers.ModelSerializer):
    main_image = serializers.SerializerMethodField()
    thumbnail = serializers.SerializerMethodField()
    name = serializers.CharField(required=False, max_length=255)

    class Meta:
        model = ItemImage
        resource_name = 'item_images'
        fields = ('id', 'avatar', 'display_order', 'item', 'main_image', 'thumbnail', 'name')

    def get_main_image(self, obj):
        logger.error(obj)
        try:
            return obj.mobile_image.url
        except AttributeError:
            return "/static/img/squarelogo.png"

    def get_thumbnail(self, obj):
        try:
            return obj.thumbnail.url
        except AttributeError:
            return "/static/img/squarelogo.png"

    def create(self, validated_data):
        
        logger.error("validated_data")
        logger.error(validated_data)

        logger.error("self.data")
        logger.error(self.data)

        item = validated_data.pop('item')
        image = ItemImage.objects.create(item=item, **validated_data)
        return image


class ItemSerializer(serializers.ModelSerializer):

    images = ItemImageSerializer(many=True, read_only=True)

    ending_date_formatted = serializers.SerializerMethodField()
    bookmarked = serializers.SerializerMethodField()
    image = serializers.SerializerMethodField()
    distance = serializers.SerializerMethodField()
    tags = serializers.SlugRelatedField(
        many=True,
        slug_field='name',
        required=False,
        read_only=True
    )
    poster_city = serializers.SerializerMethodField()
    poster_state = serializers.SerializerMethodField()
    date_joined = serializers.CharField(source="user.date_joined", required=False)
    # zipcode = serializers.SerializerMethodField()

    category = serializers.PrimaryKeyRelatedField(queryset=ItemCategory.objects.all())
    poster_username = serializers.CharField(source="user.username", required=False)
    poster_hours = serializers.CharField(source="user.profile.hours", required=False)

    # status_title = serializers.CharField(source="status.name", required=False)
    status_title = serializers.SerializerMethodField()

    avatar = serializers.ImageField(source="user.profile.avatar", read_only=True)
    owner_review = serializers.CharField(source="user.profile.average_review", read_only=True)

    class Meta:
        model = Item
        resource_name = 'items'

        fields = ('id', 'slug', 'bookmarked', 'title', 'description', 'price_per_day', 'status', 'status_title',
                  'ending_date', 'ending_date_formatted', 'images', 'location', 'image', 'distance',
                  'tags', 'category', 'poster_username', 'lockout_dates', 'zipcode', 'poster_city',
                  'poster_state', 'avatar', 'owner_review', 'poster_hours', 'date_joined')

        read_only_fields = ('slug','id', 'bookmarked', 'status', 'status_title', 
            'ending_date', 'ending_date_formatted', 'image', 'location', 'image', 'distance', 'tags', 
            'poster_username', 'lockout_dates', 'poster_state', 'poster_city', 'avatar', 'poster_hours', 'date_joined')

    def validate(self, data):

        if self.instance and self.context['request'].user != self.instance.user:
            raise serializers.ValidationError("User is not owner of this item.")
            
        return data

    def get_poster_city(self, obj):
        try:
            profile = Profile.objects.get(user=obj.user)
            return profile.city
        except Profile.DoesNotExist:
            return ""

    def get_poster_state(self, obj):
        try:
            profile = Profile.objects.get(user=obj.user)
            return profile.state
        except Profile.DoesNotExist:
            return ""


    def get_bookmarked(self, obj):
        try:
            user = self.context['request'].user
            # logger.error("user")
            # logger.error(user)
            if user.bookmarks.filter(item__id=obj.id).exists():
                return True
        except:
            pass
        return False

    def get_image(self, obj):
        if obj.main_image and obj.main_image.listing_thumbnail:
            return obj.main_image.listing_thumbnail.url
        else:
            return "/static/img/squarelogo.png"

    def get_distance(self, obj):
        try:
            return obj.get_proximity(self.context['location']['longitude'],
                                     self.context['location']['latitude'])
        except KeyError:
            return ''

    def get_ending_date_formatted(self, obj):
        # Nov. 15, 2015, midnight
        if obj.ending_date:
            return obj.ending_date.strftime("%b %d, %Y")
        return ""

    def get_status_title(self, obj):
        if obj.archived:  
            return "archived"
        else:
            return "available"

