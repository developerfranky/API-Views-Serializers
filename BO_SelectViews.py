import mailchimp
from datetime import datetime, timedelta
from django.utils import timezone
from home.utils import find_values_from_key, get_reviews
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from rest_framework.mixins import ListModelMixin, RetrieveModelMixin
from rest_framework import parsers, renderers
from rest_framework.authtoken.models import Token
from rest_framework.settings import api_settings
from rest_framework.generics import GenericAPIView
from rest_framework.serializers import Serializer
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework import mixins

from api.filters import SearchFilter, OrderingFilter
from api.mixins import CreateIntermediateModelMixin, DestroyIntermediateModelMixin, IntermediateFilterMixin, status
from api.permissions import permissions
from api.renderers import EmberJSONRenderer

import requests

from api.serializers import Response, CreateUserSerializer, GroupSerializer, \
    ItemBookmarkSerializer, EmberResultsSetPagination, \
    ItemSerializer, ItemStubSerializer, \
    AuthTokenSerializer, TagSerializer, \
    UserSerializer, SearchSerializer, ItemImageSerializer, FeaturedCategorySerializer,\
    MessagesSerializer, SingleMessageSerializer, ItemLockoutSerializer, FCMIDSerializer, \
    TransactionSerializer, TransactionReviewSerializer, BorrowRequestSerializer 

from login.models import Group, Profile, FCMID

from home.models import Item, ItemStatus, ItemBookmark, ItemImage, \
    Tag, FeaturedCategory, MessageThread, ItemLockout, Transaction, TransactionReview, \
    TransactionFailedToCreate, BorrowRequest

from django.core.exceptions import ObjectDoesNotExist
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.conf import settings
from django.http import Http404, JsonResponse
from django.contrib.auth import get_user_model
from django.db.models.query import Q, QuerySet
from django.db import IntegrityError
from django.shortcuts import redirect

from social.exceptions import AuthException
from social.apps.django_app.utils import psa

from django.core.mail import send_mail

from paypalrestsdk import Payment
from paypalrestsdk.exceptions import ResourceNotFound, ServerError
            
from django.utils.dateparse import parse_datetime

from geopy.geocoders import GoogleV3 
geocoder = GoogleV3()


from api.emails import send_message_email, send_request_received_email, send_request_accepted_email, send_request_paid_email

User = get_user_model()

import logging
logger = logging.getLogger(__name__)

from pyfcm import FCMNotification

push_service = FCMNotification(api_key=settings.FCM_SERVER_KEY)


class ObtainAuthToken(APIView):
    throttle_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AuthTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = serializer.save()
        except:
            return JsonResponse({'non_field_errors': 'Problem with request, user not logged in'})

        Token.objects.filter(user=user).delete()
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key})


class SearchView(APIView):
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = SearchSerializer
    authentication_classes = (SessionAuthentication, TokenAuthentication)

    def get(self, request):
        print('request')
        print(request.GET)
        
        serializer = self.serializer_class(data=request.GET, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        data = serializer.validated_data

        paginator = Paginator(list(data['results']), 25)  # Show 25 contacts per page

        page = request.GET.get('page', '')

        try:
            data = paginator.page(page)
        except PageNotAnInteger:
            data = paginator.page(1)
        except EmptyPage:
            data = paginator.page(paginator.num_pages)

        json_data = {
            "num_pages": data.paginator.num_pages,
            "current_page": data.number,
            "results": [result for result in data]
        }

        return Response({'search': json_data})


class UserView(APIView):
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = CreateUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        Token.objects.filter(user=user).delete()
        token, created = Token.objects.get_or_create(user=user)

        data = {"id": user.id, "success": True, "token": token.key}

        profile = Profile(user=user)
        profile = update_profile(profile, serializer.validated_data)
        profile.save()

        return Response(data, status=status.HTTP_201_CREATED)

    def get_success_headers(self, data):
        try:
            return {'Location': data[api_settings.URL_FIELD_NAME]}
        except (TypeError, KeyError):
            return {}


class TagTrendingView(GenericAPIView):
    permissin_classes = [permissions.AllowAny, ]
    serializer_class = TagSerializer

    def get(self, request, format=None):
        data = {"success": True}
        headers = self.get_success_headers(data)
        results = Item.objects.get_trending_tags()
        data = {"tags": results, "success": True}
        return Response(data, status=status.HTTP_200_OK, headers=headers)

    def get_success_headers(self, data):
        try:
            return {'Location': data[api_settings.URL_FIELD_NAME]}
        except (TypeError, KeyError):
            return {}



class ItemViewSet(ItemModelViewSet):
    paginate_by = 10
    authentication_classes = [TokenAuthentication, SessionAuthentication]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    model = Item
    serializer_class = ItemSerializer
    renderer_classes = (EmberJSONRenderer,)
    pagination_class = EmberResultsSetPagination
    queryset = Item.objects.all()

    def perform_create(self, serializer):
        print('inside perform create')
        instance = serializer.save(user=self.request.user)
        if 'tags' in self.request.data:
            tags = self.request.data.get('tags')
            tags = tags.replace(" ", "")
            tags = tags.split(',')
            Tag.objects.update_tags(instance, " ".join(tags))

    def retrieve(self, request, *args, **kwargs):
        print('inside retrieve')
        instance = self.get_object()
        serializer = self.get_serializer(instance, context={'request': request})
        return JsonResponse(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        print('inside partial update')
        instance = self.queryset.get(pk=kwargs.get('pk'))
        serializer = self.serializer_class(instance, data=request.data, context={'request': request}, partial=True)
        serializer.is_valid(raise_exception=True)
        
        if 'tags' in self.request.data:
            tags = self.request.data.get('tags')
            tags = tags.replace(" ", "")
            tags = tags.split(',')
            Tag.objects.update_tags(instance, " ".join(tags))

        serializer.save()
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        print('inside update')
        instance = self.queryset.get(pk=kwargs.get('pk'))
        serializer = self.serializer_class(instance, data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        if 'tags' in self.request.data:
            tags = self.request.data.get('tags')
            tags = tags.replace(" ", "")
            tags = tags.split(',')
            Tag.objects.update_tags(instance, " ".join(tags))

        serializer.save()
        return Response(serializer.data)
            

@psa('social:complete')
def register_by_access_token(request, backend):
    token = request.GET.get('access_token')
    try:
        user = request.backend.do_auth(token)
    except (IntegrityError, AuthException):
        return JsonResponse({'non_field_errors': 'A user with that email already exists.'})
    except:
        return JsonResponse({'non_field_errors': 'Problem with request, user not logged in'})
    if user:
        Token.objects.filter(user=user).delete()
        token, created = Token.objects.get_or_create(user=user)
        return JsonResponse({'token': token.key})
    else:
        return JsonResponse({'non_field_errors': 'Problem with request, user not logged in'})


class ImageView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    model = ItemImage
    serializer_class = ItemImageSerializer
    parser_classes = (parsers.MultiPartParser, parsers.FormParser)
    # parser_classes = (parsers.FileUploadParser)
    pagination_class = EmberResultsSetPagination

    def put(self, request, format=None):
        print('request.data')
        print(request.data)
        try:
            serializer = self.serializer_class(data=request.data)
        except:
            serializer = self.serializer_class(data=request.data.qqfile)

        serializer.is_valid(raise_exception=True)
        

        if not 'item' in self.request.data:
            return Response({"error": 'Must include attribute `item`.'}, status=status.HTTP_400_BAD_REQUEST)

        item = Item.objects.get(id=serializer.data['item'])
        if not request.user == item.user:
            raise PermissionDenied("You do not have permission to modify that Item")
        image = serializer.save()
        return Response({"success": "created image successfully: " + image.avatar.url}, status=status.HTTP_201_CREATED)


class MeView(GenericAPIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication)
    permission_classes = [permissions.IsAuthenticated]
    model = get_user_model()
    parser_classes = (parsers.JSONParser, parsers.FormParser,)
    serializer_class = UserSerializer
    renderer_classes = (EmberJSONRenderer,)

    def get(self, request, format=None):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def put(self, request):
        profile = self.request.user.profile

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        if 'profile' in serializer.validated_data:
            profile = update_profile(profile, serializer.validated_data['profile'])
            profile.save()

        return Response(serializer.validated_data)


class LentHistoryView(APIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication)
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)    

    def get(self, request):
        transactions = request.user.transactions_as_lender.all().order_by('-date_created')
        serializer = TransactionSerializer(transactions, many=True)
        return Response({'items_lent': serializer.data}, status=status.HTTP_200_OK)


class BorrowedHistoryView(APIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication)
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)    

    def get(self, request):
        transactions = request.user.transactions_as_borrower.all().order_by('-date_created')
        serializer = TransactionSerializer(transactions, many=True)
        return Response({'items_borrowed': serializer.data}, status=status.HTTP_200_OK)


class ListedItemsView(APIView):
    authentication_classes = (SessionAuthentication, TokenAuthentication)

    def get(self, request):
        items = Item.objects.filter(user=request.user)
        serializer = ItemSerializer(items, many=True)
        return Response({'items': serializer.data})


class BookmarkedListView(GenericAPIView):
    queryset = Item.objects.all()
    serializer_class = ItemStubSerializer
    authentication_classes = (SessionAuthentication, TokenAuthentication)
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser,)
    renderer_classes = (EmberJSONRenderer,)

    def get(self, request, format=None):
        queryset = self.get_queryset()
        serializer = ItemStubSerializer(queryset, many=True, context={'user':self.request.user})
        logger.error(serializer)
        return Response(serializer.data)

    def get_queryset(self):
        assert self.queryset is not None, (
            "'%s' should either include a `queryset` attribute, "
            "or override the `get_queryset()` method."
            % self.__class__.__name__
        )

        user = self.request.user
        item_bookmark_ids = user.bookmarks.values_list('item__id', flat=True)

        queryset = self.queryset.filter(pk__in=item_bookmark_ids)

        if isinstance(queryset, QuerySet):
            # Ensure queryset is re-evaluated on each request.
            queryset = queryset.all()
        return queryset



class LockoutView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    model = ItemLockout
    serializer_class = ItemLockoutSerializer
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)

    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        item = Item.objects.get(id=serializer.data['item'])

        if not request.user == item.user:
            raise PermissionDenied("You do not have permission to modify that Item")
        
        lockout = serializer.save()
        return Response({"success": "created lockout_date"})

    def get(self, request): 
        if 'item' in self.request.query_params:
            try:
                item = Item.objects.get(pk=self.request.query_params['item'])
                user = self.request.user
                
                if not (user == item.user):
                    return Response('User not owner of this item', status=status.HTTP_400_BAD_REQUEST)

                return Response({
                    'item_id': item.id,
                    'item_title': item.title,
                    'lockouts': item.lockout_dates, 
                    })
            except: 
                return Response('Item not found')
        else:
            return Response('Provide item id as a query parameter', status=status.HTTP_400_BAD_REQUEST)



class PayPalCreatePaymentView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)

    def post(self, request):
        # logger.error("request")
        # logger.error(request.META)
        logger.error("data")
        logger.error(request.data)

        if not 'borrow_request_slug' in request.data:
            return Response({"error": "Must supply BorrowRequest slug"}, status=status.HTTP_400_BAD_REQUEST)

        borrow_request = BorrowRequest.objects.get(slug=request.data['borrow_request_slug'])

        if request.user != borrow_request.borrower:
            return Response({"error": "User is not the borrower"}, status=status.HTTP_400_BAD_REQUEST)

        if borrow_request.lender_accepted != True:
            return Response({"error": "Cannot Pay for request that lender has not accepted"}, status=status.HTTP_400_BAD_REQUEST)

        item = borrow_request.item
        transaction_price = borrow_request.total_price
        start_date = str(borrow_request.date_used_start).replace(' ', 'T')
        end_date = str(borrow_request.date_used_end).replace(' ', 'T')
        days = borrow_request.duration

        start_date = start_date[:start_date.index('+')] + 'Z'
        end_date = end_date[:end_date.index('+')] + 'Z'


        today = timezone.now().date()
        _pickup = parse_datetime(start_date)
        print(today)
        print(_pickup.date())

        if _pickup.date() < today:
            return Response({"error": "Pick Up date has already passed"}, status=status.HTTP_400_BAD_REQUEST)


        payment = Payment({
            "intent": "sale",
            "payer": {
                "payment_method":"paypal"
            },
            "redirect_urls":{
                "return_url": "http://borrowonce.com",
                "cancel_url": "http://borrowonce.com"
            },
            "transactions": [
                {
                    "item_list": {
                        "items": [
                            {
                                "name": item.title,
                                "sku": item.id,
                                "price": str(item.price_per_day),
                                "currency": "USD",
                                "quantity": days 
                            }
                        ]
                    },
                    "amount": {
                        "total": str(transaction_price),
                        "currency": "USD"
                    },
                    "description": "Borrowing this item for %s days" % (days),
                    # used for validating that Transaction creation in DB
                    "custom": str(request.user.id)+','+start_date+','+end_date+','+str(borrow_request.slug)
                }
            ]
        })

        if payment.create():
            print(payment.id)
            return Response({"paymentID": payment.id})
        else:
            logger.error("Payment creation failed")
            logger.error(payment.error)
            return Response("An error has occurred.")


class PayPalExecutePaymentView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)

    def get(self, request):
        return Response('testing yo')

    def post(self, request):


        paymentID = request.data['paymentID']
        payerID = request.data['payerID']

        payment = Payment.find(paymentID)
        
        if not payment['payer']['status'] == 'VERIFIED':
            return Response(data={
                "success": False, 
                "error":"The paypal account is not verified.",
                "not_verified": True,
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )
    
        custom = payment['transactions'][0]['custom']
        item_id = payment['transactions'][0]['item_list']['items'][0]['sku']
        email = payment['payer']['payer_info']['email']
        user_id, start_date, end_date, request_slug = custom.split(',')
        start_date = parse_datetime(start_date)
        end_date = parse_datetime(end_date)

        try:
            item = Item.objects.get(pk=item_id)
        except:
            return Response({"error": "item in custom field not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        # success, message = item.test_lockout_range(start_date, end_date);
        # if not success:
        #     return Response({"error": message}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(pk=user_id)
        except:
            return Response({"error": "user not found"}, status=status.HTTP_400_BAD_REQUEST)

        if payment.execute({"payer_id": payerID}):            
            # save paypal account in user profile
            user.profile.paypal_email = email
            user.profile.is_verified = True
            user.profile.save()

            # TODO: Maybe? save history of all paypal accounts a user has used. Helps prevent fraud 
            # in case someone uses a stolen account we have a history of it.
            
            success, transaction_details = create_transaction(paymentID=paymentID, borrower=request.user, borrowRequestSlug=request_slug)
            
            if success:
                return Response(
                    data={
                        "success": True, 
                        "transaction" : transaction_details
                    }, 
                    status=status.HTTP_201_CREATED
                )
            else:
                return Response(
                    data={
                        "success": True,
                        "error" : transaction_details,
                        "message": "Payment executed but error in creating Transaction Model",
                        "details for create_transaction": transaction_details
                    }, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            # return Response({"success": True, "paymentID": payment.id})
        else:
            return Response(data={"success": False, "error":"PayPal payment execute failed."}, status=status.HTTP_400_BAD_REQUEST)
            logger.error(payment.error) # Error Hash


def create_transaction(*, paymentID=None, borrower=None, borrowRequestSlug=None):
    try:
        payment = Payment.find(paymentID)
    except ResourceNotFound:
        return False, "Wrong PayPal Payment code. Payment not found."
    except ServerError:
        # Save to another model for later attempting.
        failed_transaction = TransactionFailedToCreate(
            borrower=borrower,
            paypal_payment_id=paymentID
        )
        failed_transaction.save()
        return False, "Internal Server Error on PayPal's behalf."

    payment_details = payment.to_dict()

    if not payment_details['transactions']:
        # raise ValueError("PayPal error: No transaction found.")
        return False, "Paypal error: No transaction found"

    if not payment_details['transactions'][0]['item_list']['items']:
        return False, "PayPal error: No items found as part of that transaction."
    
    item_details = payment_details['transactions'][0]['item_list']['items'][0]
    item_id = item_details['sku']

    try:
        item = Item.objects.get(id=item_id)
    except Item.DoesNotExist:
        return False, "Item not found"

    try:
        borrower = User.objects.get(pk=borrower.id)
    except:
        return False, "Borrower not found"
    
    try:
        custom_field = payment_details['transactions'][0]['custom']
        try:
            paypal_payee_id, start_date, end_date, request_slug = custom_field.split(',')
            start_date = parse_datetime(start_date)
            end_date = parse_datetime(end_date)
        except:
            return False, "Paypal Custom Field if not of format User,Start,End,RequestSlug."
        
        try:
            paypal_payee = User.objects.get(pk=paypal_payee_id)
        except:
            return False, "Paypal payee id not found."

        if not paypal_payee == borrower:
            # print('borrower is not person who paid for paypal transaction')
            return False, "User is not payer in paypal transaction"
    except:
        # print("paypal payee id not found. Check for 'custom' field in transaction")
        return False, "Custom Field not working."

    try:
        borrow_request = BorrowRequest.objects.get(slug=request_slug)
    except BorrowRequest.DoesNotExist: 
        return False, 'Borrow Request not found'

    try:
        transaction = Transaction.objects.get(payment_id=paymentID)
        return False, 'Transaction already exists'

    except Transaction.DoesNotExist:
        borrow_request.paid = True
        borrow_request.save()
        
        transaction = Transaction(
            lender=item.user,
            borrower=borrower,
            item=item,
            payment_id=payment.id,
            date_used_start=start_date,
            date_used_end=end_date,
            days_borrowed=item_details['quantity'],  
            total_price=payment_details['transactions'][0]['amount']['total'],
            borrow_request = borrow_request
        )

        transaction.save()
        serializer = TransactionSerializer(transaction)

        send_fcm_message(
            recipient=borrow_request.lender,
            title="Payment Received!",
            body="%s has paid for %s" % (borrow_request.borrower.username, item.title),
            tag="REQUEST UPDATE"
        )
        send_request_paid_email(recipient=item.user, sender=borrower, item_name=item.title)

        return True, serializer.data

class CreateTransactionView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)

    def post(self, request):

        paymentID = request.data["paymentID"]
        success, transaction_details = create_transaction(paymentID=paymentID, borrower=request.user)
        
        if success:
            return Response(
                data={
                    "success" : transaction_details
                }, 
                status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                {
                    "error" : transaction_details
                }, 
                status=status.HTTP_400_BAD_REQUEST
            )

class CheckLockoutView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    # renderer_classes = (renderers.JSONRenderer,)

    def post(self, request, format=None):
        start_date = request.data['start_date']
        end_date = request.data['end_date']
        item_id = request.data['item']
        
        print(start_date)
        print(end_date)

        try:
            i = Item.objects.get(id=item_id)
        except Item.DoesNotExist:
            return Response({"dates_valid": False, "error":"Item not found"}, status=status.HTTP_404_NOT_FOUND)

        d1 = parse_datetime(start_date)
        d2 = parse_datetime(end_date)
        l = ItemLockout(item=i, start_date=d1, end_date=d2)
        
        try:
            l.clean()
            return Response({"dates_valid": True}, status=status.HTTP_200_OK)
        except Exception as e: 
            print("**** ERROR ****")
            print(e)
            return Response({"dates_valid": False, "error": e}, status=status.HTTP_400_BAD_REQUEST)



class AcceptBorrowRequestView(APIView):
    authentication_classes = [SessionAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (parsers.MultiPartParser, parsers.FormParser, parsers.JSONParser)
    renderer_classes = (renderers.JSONRenderer,)

    def post(self, request):
        try:
            user = User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_400_BAD_REQUEST)

        if 'borrow_request_slug' in request.data:
            try:
                borrow_request = BorrowRequest.objects.get(slug=request.data['borrow_request_slug'])
            except BorrowRequest.DoesNotExist:
                return Response(
                    {"error": "BorrowRequest Slug not found."}, status=status.HTTP_400_BAD_REQUEST) 
        else:
            return Response(
                {"error": "Must supply BorrowRequest slug."}, status=status.HTTP_400_BAD_REQUEST)

        if user != borrow_request.lender:
            return Response(
                {"error": "User not lender of this item."}, status=status.HTTP_400_BAD_REQUEST)
        
        if borrow_request.canceled == True:
            return Response(
                {"error": "Cannot accept BorrowRequest with expired status."}, status=status.HTTP_400_BAD_REQUEST)
        
        item = borrow_request.item
        start_date = borrow_request.date_used_start
        end_date = borrow_request.date_used_end
        
        ### CHECK LOCKOUTS ###
        success, message = item.test_lockout_range(start_date, end_date);
        if not success:
            return Response({"error": message, "dateConflict": True}, status=status.HTTP_400_BAD_REQUEST)

        borrow_request.lender_accepted = True
        borrow_request.save()

        # once item is accepted, create lockouts. 
        # Prevents users from requesting same days and also prevents OWNER from accepting conflicting requests.
        lockout = ItemLockout(
            item=item,
            accepted_request=borrow_request,
            start_date=start_date,
            end_date=end_date
        )
        lockout.save()

        send_fcm_message(recipient=borrow_request.borrower,
            title="Borrow Request Accepted!",
            body="%s has accepted to lend %s" % (borrow_request.lender.username, item.title),
            tag="REQUEST UPDATE"
        )
        send_request_accepted_email(recipient=borrow_request.borrower, sender=borrow_request.lender, item_name=item.title)

        serializer=BorrowRequestSerializer(borrow_request)
        return Response({
            "success": serializer.data
            }, status=status.HTTP_202_ACCEPTED)
